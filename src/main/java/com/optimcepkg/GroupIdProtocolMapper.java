package com.optimcepkg;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.*;
import java.util.stream.Stream;

public class GroupIdProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-orgs-with-roles-mapper";

    public static final String CONF_CLAIM_NAME = "claimName";
    public static final String CONF_ORGS_ROOT_PATH = "orgsRootPath";
    public static final String CONF_ROLES_MODE = "rolesMode"; // strict|loose

    public static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        List<ProviderConfigProperty> props = new ArrayList<>();

        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName(CONF_CLAIM_NAME);
        claimName.setLabel("Claim name");
        claimName.setType(ProviderConfigProperty.STRING_TYPE);
        claimName.setDefaultValue("");
        claimName.setHelpText("JWT claim name to store organizations with roles.");
        props.add(claimName);

        ProviderConfigProperty orgsRoot = new ProviderConfigProperty();
        orgsRoot.setName(CONF_ORGS_ROOT_PATH);
        orgsRoot.setLabel("Orgs root group path");
        orgsRoot.setType(ProviderConfigProperty.STRING_TYPE);
        orgsRoot.setDefaultValue("/");
        orgsRoot.setHelpText("Top-level group path containing org groups, e.g. /orgs");
        props.add(orgsRoot);

        ProviderConfigProperty rolesMode = new ProviderConfigProperty();
        rolesMode.setName(CONF_ROLES_MODE);
        rolesMode.setLabel("Roles mode");
        rolesMode.setType(ProviderConfigProperty.LIST_TYPE);
        rolesMode.setOptions(List.of("strict", "loose"));
        rolesMode.setDefaultValue("strict");
        rolesMode.setHelpText(
                "strict: only accept /orgs/<org>/roles/<ROLE>. " +
                "loose: accept /orgs/<org>/<ROLE> and /orgs/<org>/roles/<ROLE>."
        );
        props.add(rolesMode);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(props, GroupIdProtocolMapper.class);
        CONFIG_PROPERTIES = Collections.unmodifiableList(props);
    }

    @Override
    public String getId() { return PROVIDER_ID; }

    @Override
    public String getDisplayCategory() { return "Token mapper"; }

    @Override
    public String getDisplayType() { return "Organizations (id/path) with roles"; }

    @Override
    public String getHelpText() {
        return "Builds orgs:[{orgId, orgPath, roles[]}], based on group membership under /orgs.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() { return CONFIG_PROPERTIES; }

    @Override
    public String getProtocol() { return OIDCLoginProtocol.LOGIN_PROTOCOL; }

    @Override
    protected void setClaim(IDToken token,
                            ProtocolMapperModel mappingModel,
                            UserSessionModel userSession,
                            KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {

        String claimName = getConfigOrDefault(mappingModel, CONF_CLAIM_NAME, "");
        String orgsRootPath = normalizePath(getConfigOrDefault(mappingModel, CONF_ORGS_ROOT_PATH, "/"));
        String rolesMode = getConfigOrDefault(mappingModel, CONF_ROLES_MODE, "strict");

        Map<String, OrgEntry> orgs = new LinkedHashMap<>();

        Stream<GroupModel> userGroups = userSession.getUser().getGroupsStream();
        userGroups.forEach(g -> {
            String orgRootPath = extractOrgRootPath(computeGroupPath(g), orgsRootPath);
            if (orgRootPath == null) return;

            GroupModel orgRoot = findAncestorByPath(g, orgRootPath);
            if (orgRoot == null) return;

            String orgPath = normalizePath(computeGroupPath(orgRoot));
            OrgEntry entry = orgs.computeIfAbsent(orgRoot.getId(),
                    id -> new OrgEntry(orgRoot.getId(), orgPath));

            if (!g.getId().equals(orgRoot.getId())) {
                String role = extractRole(normalizePath(computeGroupPath(g)), orgPath, rolesMode);
                if (role != null && !role.isBlank()) entry.roles.add(role);
            }
        });

        List<Map<String, Object>> payload = new ArrayList<>();
        for (OrgEntry e : orgs.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("orgId", e.orgId);
            m.put("orgPath", e.orgPath);
            m.put("roles", new ArrayList<>(e.roles));
            payload.add(m);
        }

        token.getOtherClaims().put(claimName, payload);
    }

    // --- compute path ourselves ---
    private static String computeGroupPath(GroupModel group) {
        Deque<String> parts = new ArrayDeque<>();
        GroupModel current = group;
        while (current != null) {
            String name = current.getName();
            if (name != null && !name.isBlank()) parts.addFirst(name);
            current = current.getParent();
        }
        return "/" + String.join("/", parts);
    }
    private static GroupModel findOrgRootGroup(GroupModel group, String orgsRootPath) {
        String root = normalizePath(orgsRootPath);

        // Special case: "/" means "top-level groups are organizations"
        if ("/".equals(root)) {
            GroupModel current = group;
            GroupModel parent = current.getParent();
            while (parent != null) {
                current = parent;
                parent = current.getParent();
            }
            return current; // top-level group
        }

        // Normal case: org roots are direct children of orgsRootPath
        GroupModel current = group;
        while (current != null) {
            GroupModel parent = current.getParent();
            if (parent == null) return null;

            String parentPath = normalizePath(computeGroupPath(parent));
            if (root.equals(parentPath)) return current;

            current = parent;
        }
        return null;
    }

    private static String extractRole(String groupPath, String orgRootPath, String rolesMode) {
        String gp = normalizePath(groupPath);
        String op = normalizePath(orgRootPath);

        if (!gp.startsWith(op + "/")) return null;

        String remainder = gp.substring((op + "/").length()); // "roles/ADMIN" or "ADMIN" or "teams/abc"
        if ("strict".equalsIgnoreCase(rolesMode)) {
            if (!remainder.startsWith("roles/")) return null;
            return firstSegment(remainder.substring("roles/".length()));
        } else {
            if (remainder.startsWith("roles/")) {
                return firstSegment(remainder.substring("roles/".length()));
            }
            return firstSegment(remainder);
        }
    }

    private static String firstSegment(String s) {
        if (s == null) return null;
        int idx = s.indexOf('/');
        return idx >= 0 ? s.substring(0, idx) : s;
    }

    private static String normalizePath(String p) {
        if (p == null || p.isBlank()) return "";
        if (!p.startsWith("/")) p = "/" + p;
        return p.endsWith("/") && p.length() > 1 ? p.substring(0, p.length() - 1) : p;
    }

    private static String getConfigOrDefault(ProtocolMapperModel model, String key, String def) {
        if (model.getConfig() == null) return def;
        String v = model.getConfig().get(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    private static final class OrgEntry {
        final String orgId;
        final String orgPath;
        final Set<String> roles = new LinkedHashSet<>();
        OrgEntry(String orgId, String orgPath) { this.orgId = orgId; this.orgPath = orgPath; }
    }

    private static String extractOrgRootPath(String groupPath, String orgsRootPath) {
        String gp = normalizePath(groupPath);
        String root = normalizePath(orgsRootPath);

        if ("/".equals(root)) {
            // first segment after "/"
            String[] seg = gp.split("/");
            if (seg.length < 2 || seg[1].isBlank()) return null;
            return "/" + seg[1];
        }

        // root != "/"
        if (!gp.equals(root) && !gp.startsWith(root + "/")) return null;

        String remainder = gp.equals(root) ? "" : gp.substring((root + "/").length());
        if (remainder.isBlank()) return null;

        String first = remainder.contains("/") ? remainder.substring(0, remainder.indexOf('/')) : remainder;
        return root + "/" + first;
    }
    private static GroupModel findAncestorByPath(GroupModel group, String wantedPath) {
        GroupModel current = group;
        while (current != null) {
            String p = normalizePath(computeGroupPath(current));
            if (p.equals(wantedPath)) return current;
            current = current.getParent();
        }
        return null;
    }
}
