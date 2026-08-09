/*
 * SPDX-FileCopyrightText: Copyright © 2022 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.server;

import org.owasp.webgoat.lessons.webwolfintroduction.UniqueCodes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ParentConfig {

  /**
   * Lives in the parent context so the WebGoat lessons (which hand out the codes) and WebWolf's
   * incoming-requests view (which must recognize the current user's own code) share one instance.
   */
  @Bean
  public UniqueCodes uniqueCodes() {
    return new UniqueCodes();
  }
}
