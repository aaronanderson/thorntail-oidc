<%@ page import="com.mercer.digital.swarm.oidc.deployment.OIDCPrincipal" %>
Hello <%= ((OIDCPrincipal)request.getUserPrincipal()).getPreferredUserName() %>!!!
