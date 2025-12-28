/*
 * This file is part of BungeeGuard, licensed under the MIT License.
 *
 *  Copyright (c) lucko (Luck) <luck@lucko.me>
 *  Copyright (c) contributors
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

package me.levyuri.veloguard.spigot.listener;

import com.destroystokyo.paper.event.player.PlayerHandshakeEvent;
import me.levyuri.veloguard.backend.TokenStore;
import me.levyuri.veloguard.backend.listener.AbstractHandshakeListener;
import me.levyuri.veloguard.spigot.VeloGuardHandshake;
import me.levyuri.veloguard.spigot.VeloGuardBackendPlugin;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A handshake listener using Paper's {@link PlayerHandshakeEvent}.
 */
public class PaperHandshakeListener extends AbstractHandshakeListener implements Listener {

    private static final Method getOriginalSocketAddressHostname;

    static {
        Method method = null;
        try {
            method = PlayerHandshakeEvent.class.getMethod("getOriginalSocketAddressHostname");
        } catch (NoSuchMethodException ignored) {
            // Paper added this method in 1.16
        }
        getOriginalSocketAddressHostname = method;
    }

    private final Logger logger;

    public PaperHandshakeListener(VeloGuardBackendPlugin plugin, TokenStore tokenStore) {
        super(plugin, tokenStore);
        this.logger = plugin.getLogger();
    }

    @EventHandler(priority = EventPriority.LOW, ignoreCancelled = true)
    public void onHandshake(PlayerHandshakeEvent e) {
        VeloGuardHandshake decoded = VeloGuardHandshake.decodeAndVerify(e.getOriginalHandshake(), this.tokenStore);

        if (decoded instanceof VeloGuardHandshake.Fail) {
            VeloGuardHandshake.Fail fail = (VeloGuardHandshake.Fail) decoded;

            // if the logging is not throttled, we send the error message
            if (isRateLimitAllowed()) {
                String ip = "null";
                if (getOriginalSocketAddressHostname != null) {
                    try {
                        ip = (String) getOriginalSocketAddressHostname.invoke(e);
                    } catch (ReflectiveOperationException ex) {
                        this.logger.log(Level.SEVERE, "Unable to get original address", ex);
                    }
                }

                this.logger.warning("Denying connection from " + ip + " - " + (plugin.isVerbose() ? fail.describeConnection() : "") + " - reason: " + fail.reason().name());
            }

            if (fail.reason() == VeloGuardHandshake.Fail.Reason.INCORRECT_TOKEN) {
                e.setFailMessage(this.invalidTokenKickMessage);
            } else {
                e.setFailMessage(this.noDataKickMessage);
            }

            e.setFailed(true);
            return;
        }

        VeloGuardHandshake.Success data = (VeloGuardHandshake.Success) decoded;
        e.setServerHostname(data.serverHostname());
        e.setSocketAddressHostname(data.socketAddressHostname());
        e.setUniqueId(data.uniqueId());
        e.setPropertiesJson(data.propertiesJson());
        ExtraProtectionListener.SUCCESSFULLY_DECODED = true;
    }
}
