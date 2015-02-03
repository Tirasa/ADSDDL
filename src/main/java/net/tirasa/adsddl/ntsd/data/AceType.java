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
package net.tirasa.adsddl.ntsd.data;

public enum AceType {

    UNEXPECTED((byte)0xFF),
    ACCESS_ALLOWED_ACE_TYPE((byte) 0x00),
    ACCESS_DENIED_ACE_TYPE((byte) 0x01),
    SYSTEM_AUDIT_ACE_TYPE((byte) 0x02),
    SYSTEM_ALARM_ACE_TYPE((byte) 0x03),
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE((byte) 0x04),
    ACCESS_ALLOWED_OBJECT_ACE_TYPE((byte) 0x05),
    ACCESS_DENIED_OBJECT_ACE_TYPE((byte) 0x06),
    SYSTEM_AUDIT_OBJECT_ACE_TYPE((byte) 0x07),
    SYSTEM_ALARM_OBJECT_ACE_TYPE((byte) 0x08),
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE((byte) 0x09),
    ACCESS_DENIED_CALLBACK_ACE_TYPE((byte) 0x0A),
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE((byte) 0x0B),
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE((byte) 0x0C),
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE((byte) 0x0D),
    SYSTEM_ALARM_CALLBACK_ACE_TYPE((byte) 0x0E),
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE((byte) 0x0F),
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE((byte) 0x10),
    SYSTEM_MANDATORY_LABEL_ACE_TYPE((byte) 0x11),
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE((byte) 0x12),
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE((byte) 0x13);

    private final byte value;

    private AceType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static AceType parseValue(final byte value) {
        for (AceType type : AceType.values()) {
            if (type.getValue() == value) {
                return type;
            }
        }

        return null;
    }
}
