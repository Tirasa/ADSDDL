/* 
 * Copyright 2015 Tirasa.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.tirasa.adsddl.ntsd.utils;

public class GUID {

    public static String getGuidAsString(byte[] GUID) {
        final StringBuilder res = new StringBuilder();

        res.append(AddLeadingZero((int) GUID[3] & 0xFF));
        res.append(AddLeadingZero((int) GUID[2] & 0xFF));
        res.append(AddLeadingZero((int) GUID[1] & 0xFF));
        res.append(AddLeadingZero((int) GUID[0] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[5] & 0xFF));
        res.append(AddLeadingZero((int) GUID[4] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[7] & 0xFF));
        res.append(AddLeadingZero((int) GUID[6] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[8] & 0xFF));
        res.append(AddLeadingZero((int) GUID[9] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[10] & 0xFF));
        res.append(AddLeadingZero((int) GUID[11] & 0xFF));
        res.append(AddLeadingZero((int) GUID[12] & 0xFF));
        res.append(AddLeadingZero((int) GUID[13] & 0xFF));
        res.append(AddLeadingZero((int) GUID[14] & 0xFF));
        res.append(AddLeadingZero((int) GUID[15] & 0xFF));

        return res.toString();

    }

    private static String AddLeadingZero(int k) {
        return (k <= 0xF) ? "0" + Integer.toHexString(k) : Integer.toHexString(k);
    }
}
