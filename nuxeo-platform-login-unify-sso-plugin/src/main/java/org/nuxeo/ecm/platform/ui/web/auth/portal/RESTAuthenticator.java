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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.common.utils.URIUtils;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;

public class RESTAuthenticator implements NuxeoAuthenticationPlugin {
	
	private Log logger = LogFactory.getLog(RESTAuthenticator.class);
	
	private static final String URL_NAME = "url";
	
	private static final String NUXEO_URL_NAME = "nuxeo_url";

    private String url = null;
    
    private String nuxeoUrl = null;
    
    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
    	logger.info("REST baseURL: "+ baseURL);
    	logger.info("REST url: "+ url);
    	logger.info("REST RequestURI:"+httpRequest.getRequestURI());
    	logger.info("REST requestedUrl: "+ httpRequest.getRequestURL().toString());
    	Map<String, String> params = new HashMap<>();
    	if(!nuxeoUrl.endsWith("/")){
    		nuxeoUrl = nuxeoUrl + "/";
    	}
    	
    	String requestedUrl = "";
    	if(!httpRequest.getRequestURI().equals("/nuxeo/nxstartup.faces")){
    		requestedUrl = "?requestedUrl=";
    		requestedUrl += httpRequest.getRequestURI().replaceFirst("/nuxeo/", "");
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
    	if(httpRequest.getParameterValues("mail") != null && httpRequest.getParameterValues("mail").length>0){
    		mail = httpRequest.getParameterValues("mail")[0];
    		String login = httpRequest.getParameterValues("tcGid")[0];
    		javax.servlet.http.Cookie cookie = new Cookie("login", login);
    		cookie.setDomain("localhost");
    		cookie.setMaxAge(30*60);
    		httpResponse.addCookie(cookie);
    		userName = "rest_client";
    	}
        if (userName != null) {
        	httpRequest.getSession().setAttribute("userName", userName);
            return new UserIdentificationInfo(userName, userName);
        } else {
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
    		return true;
    	}
        return false;
    }
    
    public Boolean handleLogout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        return true;
    }
}