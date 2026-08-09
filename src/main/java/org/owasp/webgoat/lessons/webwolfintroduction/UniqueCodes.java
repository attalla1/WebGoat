/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Keeps the unique codes used by the WebWolf lessons. A code is generated with {@link SecureRandom}
 * and never leaves the server unless it is sent to the user it belongs to. Deriving it from the
 * username (as the original lesson did with the reversed username) would make it predictable for
 * anyone knowing that username. The WebWolf introduction lesson hands the code to the user by mail
 * and expects that very same code back on the landing page, so the mail and landing assignments
 * share the {@link #MAIL} flow key: only the code the user actually received verifies.
 */
@Component
public class UniqueCodes {

  public static final String MAIL = "mail";

  private static final char[] ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, String> codes = new ConcurrentHashMap<>();

  /**
   * Returns the code for this user and flow, generating a new one when there is none yet. The code
   * keeps the length contract of the original lesson (as long as the username) but consists of
   * securely random alphanumeric characters instead of a value derived from the username.
   */
  public String get(String username, String flow) {
    return codes.computeIfAbsent(key(username, flow), unused -> generate(username.length()));
  }

  /** Compares the given code with the one handed out to this user for this flow. */
  public boolean matches(String username, String flow, String code) {
    String expected = codes.get(key(username, flow));
    if (expected == null || code == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8));
  }

  private String key(String username, String flow) {
    return flow + ":" + username;
  }

  private String generate(int length) {
    StringBuilder code = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      code.append(ALPHABET[secureRandom.nextInt(ALPHABET.length)]);
    }
    return code.toString();
  }
}
