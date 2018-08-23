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
package net.tirasa.adsddl.it;

public final class SyncToken {

    private final Object value;

    /**
     * Creates a new
     *
     * @param value
     * May not be null. TODO: define set of allowed value types
     * (currently same as set of allowed attribute values).
     */
    public SyncToken(final Object value) {
        this.value = value;
    }

    /**
     * Returns the value for the token.
     *
     * @return The value for the token.
     */
    public Object getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "SyncToken: " + value.toString();
    }
}
