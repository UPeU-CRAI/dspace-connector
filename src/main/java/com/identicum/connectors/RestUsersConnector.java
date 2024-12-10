package com.identicum.connectors;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;

import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.core5.http.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.operations.TestApiOp;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.PreconditionFailedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.evolveum.polygon.rest.AbstractRestConnector;


@ConnectorClass(displayNameKey = "connector.identicum.rest.display", configurationClass = RestUsersConfiguration.class)
public class RestUsersConnector 
	extends AbstractRestConnector<RestUsersConfiguration> 
	implements CreateOp, UpdateOp, SchemaOp, SearchOp<RestUsersFilter>, DeleteOp, UpdateAttributeValuesOp, TestOp, TestApiOp
{
	private static final Log LOG = Log.getLog(RestUsersConnector.class);

	private static final String USERS_ENDPOINT = "/server/api/eperson/epersons";
	private static final String ROLES_ENDPOINT = "/roles";

	public static final String ATTR_FIRST_NAME = "firstName";
	public static final String ATTR_LAST_NAME = "lastName";
	public static final String ATTR_EMAIL = "email";
	public static final String ATTR_USERNAME = "username";
	public static final String ATTR_ROLES = "roles";

	// ==============================
	// Bloque de authManager y Autenticación
	// ==============================

	// authManager para manejar la autenticación
	private AuthManager authManager;

	@Override
	public void init(Configuration configuration) {
		// Llamar al método init de la superclase
		super.init(configuration);

		// Configurar el AuthManager con el tipo correcto de configuración
		RestUsersConfiguration restConfig = (RestUsersConfiguration) configuration;
		authManager = new AuthManager(restConfig);

		// Realizar autenticación al inicializar
		authManager.authenticate();
		LOG.info("Authentication completed during initialization.");
	}


	public Schema schema()
	{
		LOG.ok("Reading schema");
		SchemaBuilder schemaBuilder = new SchemaBuilder(RestUsersConnector.class);
		ObjectClassInfoBuilder accountBuilder = new ObjectClassInfoBuilder();
		accountBuilder.setType(ObjectClass.ACCOUNT_NAME);

		AttributeInfoBuilder attrUsername = new AttributeInfoBuilder(ATTR_USERNAME);
		attrUsername.setRequired(true);
		accountBuilder.addAttributeInfo(attrUsername.build());

		AttributeInfoBuilder attrEmail = new AttributeInfoBuilder(ATTR_EMAIL);
		attrEmail.setRequired(false);
		accountBuilder.addAttributeInfo(attrEmail.build());

		AttributeInfoBuilder attrFirstName = new AttributeInfoBuilder(ATTR_FIRST_NAME);
		attrFirstName.setRequired(true);
		accountBuilder.addAttributeInfo(attrFirstName.build());

		AttributeInfoBuilder attrLastName = new AttributeInfoBuilder(ATTR_LAST_NAME);
		attrLastName.setRequired(true);
		accountBuilder.addAttributeInfo(attrLastName.build());
		
		AttributeInfoBuilder attrDummy = new AttributeInfoBuilder("dummy");
		attrDummy.setRequired(false);
		accountBuilder.addAttributeInfo(attrDummy.build());
		
		AttributeInfoBuilder attrRoles = new AttributeInfoBuilder(ATTR_ROLES);
		attrRoles.setMultiValued(true);
		attrRoles.setRequired(false);
		accountBuilder.addAttributeInfo(attrRoles.build());

		schemaBuilder.defineObjectClass(accountBuilder.build());
		
		ObjectClassInfoBuilder groupBuilder = new ObjectClassInfoBuilder();
		groupBuilder.setType(ObjectClass.GROUP_NAME);
		
		schemaBuilder.defineObjectClass(groupBuilder.build());


		LOG.ok("Exiting schema");
		return schemaBuilder.build();
	}

	// ==============================
	// Bloque de Operaciones CRUD
	// ==============================

	// Este método Auxiliar se encarga de crear la estructura de metadatos compatible con DSpace:
	private JSONArray createMetadataArray(String value) {
		JSONArray metadataArray = new JSONArray();
		JSONObject metadataObj = new JSONObject();
		metadataObj.put("value", value);
		metadataObj.put("language", JSONObject.NULL);
		metadataObj.put("authority", JSONObject.NULL);
		metadataObj.put("confidence", -1);
		metadataObj.put("place", 0);
		metadataArray.put(metadataObj);
		return metadataArray;
	}

	public Uid create(ObjectClass objectClass, Set<Attribute> attributes, OperationOptions operationOptions) {
		LOG.ok("Entering create with objectClass: {0}", objectClass.toString());
		JSONObject response = null;
		JSONObject jo = new JSONObject();
		JSONObject metadata = new JSONObject();

		for (Attribute attr : attributes) {
			LOG.ok("Reading attribute {0} with value {1}", attr.getName(), attr.getValue());
			String attrName = attr.getName();

			switch (attrName) {
				case "firstname":
					metadata.put("eperson.firstname", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "lastname":
					metadata.put("eperson.lastname", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "language":
					metadata.put("eperson.language", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "email":
					jo.put("email", getStringAttr(attributes, attrName));
					break;
				case "netid":
					jo.put("netid", getStringAttr(attributes, attrName));
					break;
				case "canLogIn":
					jo.put("canLogIn", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "requireCertificate":
					jo.put("requireCertificate", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "selfRegistered":
					jo.put("selfRegistered", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "name":
					jo.put("name", getStringAttr(attributes, attrName));
					break;
			}
		}

		jo.put("metadata", metadata);

		// Construir el endpoint completo usando USERS_ENDPOINT
		String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + USERS_ENDPOINT;

		HttpPost request = new HttpPost(endpoint);
		StringEntity entity = new StringEntity(jo.toString(), ContentType.APPLICATION_JSON);
		request.setEntity(entity);

		try {
			// Llamar al método callRequest con autenticación
			String result = callRequest(request, jo, true);
			response = new JSONObject(result);
		} catch (IOException | ParseException | URISyntaxException e) {
			throw new RuntimeException("Error during request execution", e);
		}

		// Obtener los enlaces del response
		String selfLink = response.getJSONObject("_links").getJSONObject("self").getString("href");
		String groupsLink = response.getJSONObject("_links").getJSONObject("groups").getString("href");

		LOG.info("Self Link: {0}", selfLink);
		LOG.info("Groups Link: {0}", groupsLink);

		String newUid = response.getString("id");
		LOG.info("response UID: {0}", newUid);
		return new Uid(newUid);
	}

	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
		LOG.ok("Entering update with objectClass: {0}", objectClass.toString());
		JSONObject response = null;
		JSONObject jo = new JSONObject();
		JSONObject metadata = new JSONObject();

		for (Attribute attribute : attributes) {
			LOG.info("Update - Atributo recibido {0}: {1}", attribute.getName(), attribute.getValue());
			String attrName = attribute.getName();

			switch (attrName) {
				case "firstname":
					metadata.put("eperson.firstname", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "lastname":
					metadata.put("eperson.lastname", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "language":
					metadata.put("eperson.language", createMetadataArray(getStringAttr(attributes, attrName)));
					break;
				case "email":
					jo.put("email", getStringAttr(attributes, attrName));
					break;
				case "netid":
					jo.put("netid", getStringAttr(attributes, attrName));
					break;
				case "canLogIn":
					jo.put("canLogIn", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "requireCertificate":
					jo.put("requireCertificate", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "selfRegistered":
					jo.put("selfRegistered", Boolean.parseBoolean(getStringAttr(attributes, attrName)));
					break;
				case "name":
					jo.put("name", getStringAttr(attributes, attrName));
					break;
			}
		}

		jo.put("metadata", metadata);

		// Construir el endpoint completo usando USERS_ENDPOINT y el UID
		String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + USERS_ENDPOINT + uid.getUidValue();

		HttpPut request = new HttpPut(endpoint);
		StringEntity entity = new StringEntity(jo.toString(), ContentType.APPLICATION_JSON);
		request.setEntity(entity);

		try {
			// Llamar al método callRequest con autenticación
			String result = callRequest(request, jo, true);
			response = new JSONObject(result);
		} catch (IOException | ParseException | URISyntaxException e) {
			throw new RuntimeException("Error modificando usuario por REST", e);
		}

		// Obtener los enlaces del response
		String selfLink = response.getJSONObject("_links").getJSONObject("self").getString("href");
		String groupsLink = response.getJSONObject("_links").getJSONObject("groups").getString("href");

		LOG.info("Self Link: {0}", selfLink);
		LOG.info("Groups Link: {0}", groupsLink);

		String newUid = response.getString("id");
		LOG.info("response UID: {0}", newUid);
		return new Uid(newUid);
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		LOG.ok("Entering delete with objectClass: {0}", objectClass.toString());

		try {
			// Validar que el ObjectClass sea ACCOUNT para eperson
			if (!ObjectClass.ACCOUNT.is(objectClass.getObjectClassValue())) {
				throw new ConnectorException("Unsupported object class for delete operation: " + objectClass);
			}

			// Construir el endpoint para eliminar el eperson
			String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + USERS_ENDPOINT + uid.getUidValue();
			LOG.info("Deleting eperson with UID {0} at endpoint {1}", uid.getUidValue(), endpoint);

			HttpDelete request = new HttpDelete(endpoint);

			// Llamar al método callRequest sin cuerpo (null para el JSONObject) y con autenticación
			callRequest(request, null, true);

			LOG.info("Eperson with UID {0} deleted successfully", uid.getUidValue());

		} catch (UnknownUidException e) {
			LOG.warn("Eperson with UID {0} not found: {1}", uid.getUidValue(), e.getMessage());
			throw e;
		} catch (Exception io) {
			throw new RuntimeException("Error eliminando usuario por REST", io);
		}
	}

	@Override
	public Uid addAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
		LOG.ok("Entering addValue with objectClass: {0}", objectClass.toString());
		try {
			for (Attribute attribute : attributes) {
				LOG.info("AddAttributeValue - Atributo recibido {0}: {1}", attribute.getName(), attribute.getValue());

				if (attribute.getName().equals("roles")) {
					List<Object> addedRoles = attribute.getValue();

					for (Object role : addedRoles) {
						JSONObject json = new JSONObject();
						json.put("id", role.toString());

						String endpoint = String.format("%s/%s/%s/%s",
								getConfiguration().getServiceAddress().replaceAll("/$", ""),
								USERS_ENDPOINT, uid.getUidValue(), ROLES_ENDPOINT);

						LOG.info("Adding role {0} for user {1} on endpoint {2}", role.toString(), uid.getUidValue(), endpoint);

						// Crear la solicitud HttpPost
						HttpPost request = new HttpPost(endpoint);

						// Convertir el JSONObject a un StringEntity y agregarlo a la solicitud
						StringEntity entity = new StringEntity(json.toString(), ContentType.APPLICATION_JSON);
						request.setEntity(entity);

						// Ejecutar la solicitud con `callRequest` pasando `true` para `withAuth`
						callRequest(request, json, true);
					}
				}
			}
		} catch (Exception io) {
			throw new RuntimeException("Error modificando usuario por REST", io);
		}
		return uid;
	}

	@Override
	public Uid removeAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions operationOptions) {
		LOG.ok("Entering removeValue with objectClass: {0}", objectClass.toString());
		try {
			for (Attribute attribute : attributes) {
				LOG.info("RemoveAttributeValue - Atributo recibido {0}: {1}", attribute.getName(), attribute.getValue());

				if (attribute.getName().equals("roles")) {
					List<Object> revokedRoles = attribute.getValue();

					for (Object role : revokedRoles) {
						String endpoint = String.format("%s/%s/%s/%s/%s",
								getConfiguration().getServiceAddress().replaceAll("/$", ""),
								USERS_ENDPOINT, uid.getUidValue(), ROLES_ENDPOINT, role.toString());

						LOG.info("Revoking role {0} for user {1} on endpoint {2}", role.toString(), uid.getUidValue(), endpoint);

						// Crear la solicitud HttpDelete
						HttpDelete request = new HttpDelete(endpoint);

						// Ejecutar la solicitud con `callRequest` pasando `true` para `withAuth`
						callRequest(request, null, true);
					}
				}
			}
		} catch (Exception io) {
			throw new RuntimeException("Error modificando usuario por REST", io);
		}
		return uid;
	}


	// ==============================
	// Bloque de Manejo de Solicitudes HTTP
	// ==============================

	protected String callRequest(HttpUriRequest request, JSONObject jo, boolean withAuth) throws IOException, ParseException, URISyntaxException {
		LOG.ok("Request URI: {0}", request.getUri());

		if (jo != null) {
			LOG.ok("Request body: {0}", jo.toString());
		}

		// Configurar encabezado Content-Type
		request.setHeader("Content-Type", "application/json");

		// Configurar encabezados de autenticación si se requiere
		if (withAuth) {
			request.setHeader("Authorization", authManager.getTokenName() + " " + authManager.getTokenValue());
			request.setHeader("X-XSRF-TOKEN", authManager.getCsrfToken());
			request.setHeader("Cookie", "DSPACE-XSRF-COOKIE=" + authManager.getCsrfToken());

			LOG.ok("Authorization header: {0}", authManager.getTokenName() + " " + authManager.getTokenValue());
			LOG.ok("X-XSRF-TOKEN header: {0}", authManager.getCsrfToken());
		}

		try (ClassicHttpResponse response = (ClassicHttpResponse) execute(request)) {
			LOG.ok("Response status: {0}", response.getCode());
			this.processResponseErrors((CloseableHttpResponse) response);

			String result = EntityUtils.toString(response.getEntity());
			LOG.ok("Response body: {0}", result);

			return result;
		} catch (IOException e) {
			throw new ConnectorException("Error reading API response.", e);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	
	public void processResponseErrors(CloseableHttpResponse response) {
		int statusCode = response.getCode();
		if (statusCode >= 200 && statusCode <= 299) {
            return;
        }
        String responseBody = null;
        try {
            responseBody = EntityUtils.toString(response.getEntity());
        } catch (IOException | ParseException e) {
            LOG.warn("cannot read response body: " + e, e);
        }

		String message = "HTTP error " + statusCode + " " + response.getReasonPhrase() + " : " + responseBody;
        LOG.error("{0}", message);
        if (statusCode == 400 || statusCode == 405 || statusCode == 406) {
            closeResponse(response);
            throw new ConnectorIOException(message);
        }
        if (statusCode == 401 || statusCode == 402 || statusCode == 403 || statusCode == 407) {
            closeResponse(response);
            throw new PermissionDeniedException(message);
        }
        if (statusCode == 404 || statusCode == 410) {
            closeResponse(response);
            throw new UnknownUidException(message);
        }
        if (statusCode == 408) {
            closeResponse(response);
            throw new OperationTimeoutException(message);
        }
        if (statusCode == 409) {
            closeResponse(response);
            throw new AlreadyExistsException();
        }
        if (statusCode == 412) {
            closeResponse(response);
            throw new PreconditionFailedException(message);
        }
        if (statusCode == 418) {
            closeResponse(response);
            throw new UnsupportedOperationException("Sorry, no cofee: " + message);
        }
        // TODO: other codes
        closeResponse(response);
        throw new ConnectorException(message);
    }

	@Override
	public FilterTranslator<RestUsersFilter> createFilterTranslator(ObjectClass arg0, OperationOptions arg1)
	{
		return new RestUsersFilterTranslator();
	}

	@Override
	public void executeQuery(ObjectClass objectClass, RestUsersFilter query, ResultsHandler handler, OperationOptions options) {
		try {
			LOG.info("executeQuery on {0}, query: {1}, options: {2}", objectClass, query, options);

			if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
				// Buscar por Uid (Primary Key del usuario)
				if (query != null && query.byUid != null) {
					String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + USERS_ENDPOINT + "/" + query.byUid;
					HttpGet request = new HttpGet(endpoint);

					// Llamar a callRequest con `true` para `withAuth`
					JSONObject response = new JSONObject(callRequest(request, null, true));

					// Convertir la respuesta JSON a ConnectorObject
					ConnectorObject connectorObject = convertUserToConnectorObject(response);
					LOG.info("Calling handler.handle on single object of AccountObjectClass");
					handler.handle(connectorObject);
					LOG.info("Called handler.handle on single object of AccountObjectClass");

				} else {
					// Aplicar filtros para la búsqueda de múltiples usuarios
					String filters = "";
					if (query != null && StringUtil.isNotBlank(query.byUsername)) {
						filters = "?username=" + query.byUsername;
					}

					String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + USERS_ENDPOINT + filters;
					HttpGet request = new HttpGet(endpoint);

					LOG.info("Calling handleUsers for multiple objects of AccountObjectClass");
					handleUsers(request, handler, options, false);
					LOG.info("Called handleUsers for multiple objects of AccountObjectClass");
				}

			} else if (objectClass.is(ObjectClass.GROUP_NAME)) {
				// Buscar por Uid (Primary Key del grupo)
				if (query != null && query.byUid != null) {
					String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + ROLES_ENDPOINT + "/" + query.byUid;
					HttpGet request = new HttpGet(endpoint);

					// Llamar a callRequest con `true` para `withAuth`
					JSONObject response = new JSONObject(callRequest(request, null, true));

					// Convertir la respuesta JSON a ConnectorObject
					ConnectorObject connectorObject = convertRoleToConnectorObject(response);
					LOG.info("Calling handler.handle on single object of GroupObjectClass");
					handler.handle(connectorObject);
					LOG.info("Called handler.handle on single object of GroupObjectClass");

				} else {
					// Aplicar filtros para la búsqueda de múltiples roles
					String filters = "";
					if (query != null && StringUtil.isNotBlank(query.byName)) {
						filters = "?name=" + query.byName;
					}

					String endpoint = getConfiguration().getServiceAddress().replaceAll("/$", "") + ROLES_ENDPOINT + filters;
					HttpGet request = new HttpGet(endpoint);

					LOG.info("Calling handleRoles for multiple objects of GroupObjectClass");
					handleRoles(request, handler, options, false);
					LOG.info("Called handleRoles for multiple objects of GroupObjectClass");
				}
			}

		} catch (IOException | ParseException | URISyntaxException e) {
			LOG.error("Error querying objects on Rest Resource", e);
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	private boolean handleUsers(HttpGet request, ResultsHandler handler, OperationOptions options, boolean findAll) throws IOException, ParseException, URISyntaxException {
		// Llamar a `callRequest` con `null` para el `JSONObject` y `true` para `withAuth`
		String responseString = callRequest(request, null, true);
		JSONArray users;

		try {
			// Verificar si la respuesta es un JSONArray o un JSONObject
			if (responseString.startsWith("[")) {
				users = new JSONArray(responseString);
			} else {
				JSONObject user = new JSONObject(responseString);
				users = new JSONArray();
				users.put(user); // Agregar el JSONObject a un JSONArray para procesarlo como lista
			}
		} catch (JSONException e) {
			LOG.error("Error parsing JSON response", e);
			throw new ConnectorException("Error parsing JSON response", e);
		}

		LOG.ok("Number of users: {0}", users.length());

		for (int i = 0; i < users.length(); i++) {
			// Solo campos básicos
			JSONObject user = users.getJSONObject(i);
			ConnectorObject connectorObject = convertUserToConnectorObject(user);

			LOG.info("Calling handler.handle inside loop. Iteration #{0}", String.valueOf(i));
			boolean finish = !handler.handle(connectorObject);
			LOG.info("Called handler.handle inside loop. Iteration #{0}", String.valueOf(i));

			if (finish) {
				return true;
			}
		}
		return false;
	}


	private ConnectorObject convertUserToConnectorObject(JSONObject user) throws IOException
	{
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid(new Uid(user.get("id").toString()));
		builder.setName(user.getString(ATTR_USERNAME));
		
		addAttr(builder, ATTR_EMAIL, user.getString(ATTR_EMAIL));
		addAttr(builder, ATTR_FIRST_NAME, user.getString(ATTR_FIRST_NAME));
		addAttr(builder, ATTR_LAST_NAME, user.getString(ATTR_LAST_NAME));

		ConnectorObject connectorObject = builder.build();
		LOG.ok("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}", user.get("id").toString(), connectorObject);
		return connectorObject;
	}

	private boolean handleRoles(HttpGet request, ResultsHandler handler, OperationOptions options, boolean findAll) throws IOException, ParseException, URISyntaxException {
		// Llamar a `callRequest` con `null` para el `JSONObject` y `true` para `withAuth`
		JSONArray roles = new JSONArray(callRequest(request, null, true));
		LOG.ok("Number of roles: {0}", roles.length());

		for (int i = 0; i < roles.length(); i++) {
			// Solo campos básicos
			JSONObject role = roles.getJSONObject(i);
			ConnectorObject connectorObject = convertRoleToConnectorObject(role);

			LOG.info("Calling handler.handle inside loop. Iteration #{0}", String.valueOf(i));
			boolean finish = !handler.handle(connectorObject);
			LOG.info("Called handler.handle inside loop. Iteration #{0}", String.valueOf(i));

			if (finish) {
				return true;
			}
		}
		return false;
	}
	
	private ConnectorObject convertRoleToConnectorObject(JSONObject role) throws IOException
	{
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid(new Uid(role.get("id").toString()));
		builder.setName(role.getString("name"));

		ConnectorObject connectorObject = builder.build();
		LOG.ok("convertRoleToConnectorObject, user: {0}, \n\tconnectorObject: {1}", role.get("id").toString(), connectorObject);
		return connectorObject;
	}

	@Override
	public void test() {
		LOG.info("Testing connector. Authentication already performed during initialization.");
	}

}