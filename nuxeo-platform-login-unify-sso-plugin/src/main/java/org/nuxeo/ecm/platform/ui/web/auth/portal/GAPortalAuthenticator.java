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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    private String url = null;
    
    private String nuxeoUrl = null;
    
    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    public Boolean handleLoginPrompt(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String baseURL) {
    	logger.info("baseURL: "+ baseURL);
    	logger.info("url: "+ url);
    	Map<String, String> params = new HashMap<>();
    	if(!nuxeoUrl.endsWith("/")){
    		nuxeoUrl = nuxeoUrl + "/";
    	}
    	params.put("URL", nuxeoUrl+"nxstartup.faces");
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
    	}
 
	    logger.info("mail: "+mail);
    	if(mail != null){
	        UserManager userManager=Framework.getService(UserManager.class);
	        Map<String, Serializable> map = new HashMap();
	        map.put("email", mail);
	        DocumentModelList userList = userManager.searchUsers(map, null);
	        if(userList != null && userList.size() > 0){
	        	DocumentModel user = userList.get(0);
	        	userName = (String) user.getPropertyValue("username");
	        }
    	}
    	logger.info("userName: "+userName);
       
 
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
}