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

package net.tirasa.adsddl.ntsd.data;

import java.util.ArrayList;
import java.util.List;

public enum AceObjectFlag {

    OTHERS(0x00000000),
    ACE_OBJECT_TYPE_PRESENT(0x00000001),
    ACE_INHERITED_OBJECT_TYPE_PRESENT(0x00000002);

    private int value;

    private AceObjectFlag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private void setValue(final int value) {
        this.value = value;
    }

    public static List<AceObjectFlag> parseValue(final int value) {
        final List<AceObjectFlag> res = new ArrayList<>();

        int remains = value;
        for (AceObjectFlag type : AceObjectFlag.values()) {
            if (type != OTHERS && (value & type.getValue()) == type.getValue()) {
                res.add(type);
                remains -= type.getValue();
            }
        }

        if (remains != 0) {
            AceObjectFlag others = AceObjectFlag.OTHERS;
            others.setValue(remains);
            res.add(others);
        }

        return res;
    }
}
