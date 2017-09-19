/**
 * jon.knight@forgerock.com
 *
 * A node that returns true if the user's email address is recorded as breached by the HaveIBeenPwned website (http://haveibeenpwned.com)
 * or false if no breach has been recorded
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;

import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import java.util.Set;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;


@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = HaveIBeenPwnedNode.Config.class)
public class HaveIBeenPwnedNode extends AbstractDecisionNode {

    interface Config {
    }

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "HaveIBeenPwnedNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public HaveIBeenPwnedNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(),context.sharedState.get(REALM).asString());
        String attr = "";

        debug.message("[" + DEBUG_FILE + "]: Looking for mail attribute");

        try {
            Set<String> idAttrs = userIdentity.getAttribute("mail");
            if (idAttrs == null || idAttrs.isEmpty()) {
                debug.error("[" + DEBUG_FILE + "]: " + "Unable to find mail attribute");
            } else {
                attr = idAttrs.iterator().next();
                debug.error("[" + DEBUG_FILE + "]: " + attr);
            }
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error getting email atttibute '{}' ", e);
        } catch (SSOException e) {
           debug.error("[" + DEBUG_FILE + "]: " + "Node exception", e);
        }

        return goTo(haveIBeenPwned(attr)).build();
    }


    private boolean haveIBeenPwned(String mail) {
        String json = "";
        try {
            URL url = new URL("https://haveibeenpwned.com/api/v2/breachedaccount/" + mail);
            debug.message("[" + DEBUG_FILE + "]: url = " + url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.33 Safari/537.36");
            if (conn.getResponseCode() == 404) {
                debug.message("[" + DEBUG_FILE + "]: response 404 - no breaches found");
                return false;
            }
            if (conn.getResponseCode() != 200) {
                debug.message("[" + DEBUG_FILE + "]: HTTP failed, response code:" + conn.getResponseCode());
                throw new RuntimeException("[" + DEBUG_FILE + "]: HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                json = json + output;
            }
            conn.disconnect();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return true;
    }

}
