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

public enum AceRight {

    OTHERS(0x00000000),
    GR(0x80000000),
    GW(0x40000000),
    GX(0x20000000),
    GA(0x10000000),
    MA(0x02000000),
    AS(0x01000000),
    SY(0x00100000),
    WO(0x00080000),
    WD(0x00040000),
    RC(0x00020000),
    SD(0x00010000),
    FA(0x001F01FF),
    FX(0x001200A0),
    FW(0x00100116),
    FR(0x00120089),
    KA(0x00000019),
    KR(0x0000003F),
    KX(0x00000019),
    KW(0x00000006),
    CR(0x00000100),
    LO(0x00000080),
    DT(0x00000040),
    WP(0x00000020),
    RP(0x00000010),
    SW(0x00000008),
    LC(0x00000004),
    DC(0x00000002),
    CC(0x00000001);

    private int value;

    private AceRight(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private void setValue(final int value) {
        this.value = value;
    }

    public static List<AceRight> parseValue(final int value) {
        final List<AceRight> res = new ArrayList<>();

        int remains = value;
        for (AceRight type : AceRight.values()) {
            if (type != OTHERS && (value & type.getValue()) == type.getValue()) {
                res.add(type);
                remains -= type.getValue();
            }
        }

        if (remains != 0) {
            AceRight others = AceRight.OTHERS;
            others.setValue(remains);
            res.add(others);
        }

        return res;
    }
}
