<%@ page import="com.mercer.cpsg.swarm.oidc.deployment.OIDCPrincipal" %>
Hello <%= ((OIDCPrincipal)request.getUserPrincipal()).getPreferredUserName() %>!!!
