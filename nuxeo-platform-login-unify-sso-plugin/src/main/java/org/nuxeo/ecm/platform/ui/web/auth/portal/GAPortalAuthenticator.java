/*
 * (C) Copyright 2006-2007 Nuxeo SAS (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 */

package org.nuxeo.ecm.platform.ui.web.auth.portal;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.common.utils.URIUtils;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;

public class GAPortalAuthenticator implements NuxeoAuthenticationPlugin {
	
	private Log logger = LogFactory.getLog(GAPortalAuthenticator.class);
	
	private static final String URL_NAME = "url";
	
	private static final String NUXEO_URL_NAME = "nuxeo_url";
	
	private static final String USER_NOT_FOUND = "User not found.";

    private String url = null;
    
    private String nuxeoUrl = null;
    
    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
    	logger.info("baseURL: "+ baseURL);
    	logger.info("url: "+ url);
    	logger.info("RequestURI:"+httpRequest.getRequestURI());
    	logger.info("requestedUrl: "+ httpRequest.getRequestURL().toString());
    	Map<String, String> params = new HashMap<>();
    	if(!nuxeoUrl.endsWith("/")){
    		nuxeoUrl = nuxeoUrl + "/";
    	}
    	
    	String requestedUrl = "";
    	if(!httpRequest.getRequestURI().equals("/nuxeo/nxstartup.faces")){
    		requestedUrl = "?requestedUrl=";
    		requestedUrl += httpRequest.getRequestURI().replaceFirst("/nuxeo/", "");
    		/*try {
				requestedUrl = URLEncoder.encode(requestedUrl, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				logger.error("Error while encoding requestedUrl " + requestedUrl, e);
			}*/
    	}
    	
    	params.put("URL", nuxeoUrl+"nxstartup.faces"+requestedUrl);
    	try {
          httpResponse.sendRedirect(URIUtils.addParametersToURIQuery(url, params));
          return true;
	    } catch (IOException e) {
	      logger.error(e);
	       return false;
	    }
    }

    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
    	String mail = null;
    	String userName = null;
    	String login = null;
    	String firstName = null;
    	String lastName = null;
    	if(httpRequest.getParameterValues("mail") != null && httpRequest.getParameterValues("mail").length>0){
    		mail = httpRequest.getParameterValues("mail")[0];   		
    		login = httpRequest.getParameterValues("tcGid")[0];
    		javax.servlet.http.Cookie cookie = new Cookie("login", login);   	
    		firstName = httpRequest.getParameterValues("givenName")[0];
    		cookie.setPath("/");
    		cookie.setMaxAge(60*60);
    		cookie.setSecure(false);
    		httpResponse.addCookie(cookie);
    		logger.info("path ends with: "+ httpRequest.getRequestURI());
    	}
 
	    logger.info("mail: "+mail);
	    UserManager userManager=Framework.getService(UserManager.class);
    	if(mail != null){
	        Map<String, Serializable> map = new HashMap();
	        map.put("email", mail);
	        
	        DocumentModelList userList = userManager.searchUsers(map, null);
	        if(userList != null && userList.size() > 0){
	        	DocumentModel user = userList.get(0);
	        	userName = (String) user.getPropertyValue("username");
	        }else{
	        	//create user in nuxeo	        	
	        	DocumentModel userModel=userManager.getBareUserModel();
	        	String schemaName=userManager.getUserSchemaName();
	        	userModel.setProperty(schemaName,"username",login);
	        	PasswordGenerator pg = new PasswordGenerator();
	        	userModel.setProperty(schemaName,"password",pg.nextPassword());
	        	userModel.setProperty(schemaName, "email", mail);
	        	userModel.setProperty(schemaName, "firstName", firstName);
	        	userModel.setProperty(schemaName, "lastName", lastName);
	       
	        	ArrayList<String> groups=new ArrayList<String>();
	        	//if user is from portal add him to the partners
	        	groups.add("partners");
	        	//TODO else add him to the member list
	        	//groups.add("members");
	        	userModel.setProperty("user","groups",groups);
	        	userModel=userManager.createUser(userModel);
	        	userName = login;
	        }
    	}
    	logger.info("userName: "+userName);
       
 
        if (userName != null) {
        	httpRequest.getSession().setAttribute("userName", userName);
            return new UserIdentificationInfo(userName, userName);
        } else {
        	if(httpRequest.getParameterValues("mail") != null){
        		httpRequest.getSession().setAttribute("flag", USER_NOT_FOUND);
        	}
        	return null;
        }
    }

    public void initPlugin(Map<String, String> parameters) {
    	this.url = parameters.get(URL_NAME);
    	this.nuxeoUrl = parameters.get(NUXEO_URL_NAME);
    }

    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
    	logger.info("needLoginPrompt");
    	String userName = null;
    	try{
    		userName = (String)httpRequest.getSession().getAttribute("userName");
    	}catch(Exception e){
    		logger.error(e);
    	}
    	if(userName == null){
    		try{
        		String flag = (String)httpRequest.getSession().getAttribute("flag");
        		if((USER_NOT_FOUND).equals(flag)){
        			return false;
        		}
        	}catch(Exception e){
        		logger.error(e);
        	}
    		return true;
    		
    	}
        return false;
    }
    
    public Boolean handleLogout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        return true;
    }
    
    

    private final class PasswordGenerator {
      private SecureRandom random = new SecureRandom();

      public String nextPassword() {
        return new BigInteger(130, random).toString(32);
      }
    }
}