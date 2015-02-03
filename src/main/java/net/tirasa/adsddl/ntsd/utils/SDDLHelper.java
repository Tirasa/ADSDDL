/**
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.ntsd.utils;

import java.util.Arrays;
import java.util.List;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;

public class SDDLHelper {

    public static final String UCP_OBJECT_GUID = "ab721a53-1e2f-11d0-9819-00aa0040529b";

    public static boolean isUserCannotChangePassword(final SDDL sddl) {
        boolean res = false;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; !res && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1) {
                        if ((Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                                || (Arrays.equals(
                                        sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a }))) {
                            res = true;
                        }
                    }
                }
            }
        }

        return res;
    }

    public static SDDL userCannotChangePassword(final SDDL sddl, final Boolean cannot) {
        final AceType type = cannot ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

        ACE self = null;
        ACE all = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; (all == null || self == null) && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1) {
                        if (self == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 })) {
                            self = ace;
                            self.setType(type);
                        } else if (all == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a })) {
                            all = ace;
                            all.setType(type);
                        }
                    }
                }
            }
        }

        if (self == null) {
            // prepare aces
            self = ACE.newInstance(type);
            self.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            self.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
            self.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000001));
            sid.addSubAuthority(NumberFacility.getBytes(0));
            self.setSid(sid);
            sddl.getDacl().getAces().add(self);
        }

        if (all == null) {
            all = ACE.newInstance(type);
            all.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            all.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
            all.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            final SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000005));
            sid.addSubAuthority(NumberFacility.getBytes(0x0A));
            all.setSid(sid);
            sddl.getDacl().getAces().add(all);
        }

        return sddl;
    }
}
