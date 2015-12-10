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
package net.tirasa.adsddl.unit;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class RetrieveTest extends AbstractTest {

    @Test
    public void unMarshall() throws Exception {
        final byte[] src = IOUtils.toByteArray(this.getClass().getResourceAsStream(SDDL_ALL_SAMPLE));
        UnMarshall(src);
    }

    @Test
    public void userChangePassword() throws Exception {
        final byte[] src = IOUtils.toByteArray(this.getClass().getResourceAsStream(DACL_ONLY_SAMPLE));
        UserChangePassword(src);
    }

    @Test
    public void ucpChangeUnMarshall() throws Exception {
        final byte[] src = IOUtils.toByteArray(this.getClass().getResourceAsStream(DACL_ONLY_SAMPLE));
        ucpChangeUnMarshall(src);
    }
}
