package com.identicum.connectors;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

public class RestUsersFilterTranslator extends AbstractFilterTranslator<RestUsersFilter> {
    private static final Log LOG = Log.getLog(RestUsersFilter.class);

    @Override
    protected RestUsersFilter createEqualsExpression(EqualsFilter filter, boolean not) {
        LOG.ok("createEqualsExpression, filter: {0}, not: {1}", filter, not);

        if (not) {
            throw new UnsupportedOperationException("NOT operation is not supported by this connector.");
        }

        Attribute attr = filter.getAttribute();
        LOG.ok("attr.getName: {0}, attr.getValue: {1}, Uid.NAME: {2}, Name.NAME: {3}",
                attr.getName(), attr.getValue(), Uid.NAME, Name.NAME);

        if (Uid.NAME.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                RestUsersFilter lf = new RestUsersFilter();
                lf.byUid = String.valueOf(attr.getValue().get(0));
                LOG.ok("lf.byUid: {0}", lf.byUid);
                return lf;
            }
        } else if (RestUsersConnector.ATTR_USERNAME.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                RestUsersFilter lf = new RestUsersFilter();
                lf.byUsername = String.valueOf(attr.getValue().get(0));
                LOG.ok("lf.byUsername: {0}", lf.byUsername);
                return lf;
            }
        } else if (RestUsersConnector.ATTR_EMAIL.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                RestUsersFilter lf = new RestUsersFilter();
                lf.byEmail = String.valueOf(attr.getValue().get(0));
                LOG.ok("lf.byEmail: {0}", lf.byEmail);
                return lf;
            }
        } else if (Name.NAME.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                RestUsersFilter lf = new RestUsersFilter();
                lf.byName = String.valueOf(attr.getValue().get(0));
                LOG.ok("lf.byName: {0}", lf.byName);
                return lf;
            }
        }

        // Si el atributo no coincide con los casos anteriores, devolver null
        LOG.warn("Unsupported attribute for filtering: {0}", attr.getName());
        return null;
    }
}
