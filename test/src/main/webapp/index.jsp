<%@ page import="com.mercer.cpsg.swarm.oidc.OIDCPrincipal" %>
Hello <%= ((OIDCPrincipal)request.getUserPrincipal()).getPreferredUserName() %>!!!
