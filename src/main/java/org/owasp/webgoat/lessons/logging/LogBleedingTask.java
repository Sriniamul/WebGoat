/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogBleedingTask implements AssignmentEndpoint {

  // Intentionally using Log4j directly (vulnerable to CVE-2021-44228 Log4Shell)
  private static final Logger log = LogManager.getLogger(LogBleedingTask.class);
  private final String password;

  public LogBleedingTask() {
    this.password = UUID.randomUUID().toString();
    log.info(
        "Password for admin: {}",
        Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8)));
  }

  @PostMapping("/LogSpoofing/log-bleeding")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    log.info("Login attempt for user: {}", username);
    if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
      return failed(this).output("Please provide username (Admin) and password").build();
    }

    if (username.equals("Admin") && password.equals(this.password)) {
      return success(this).build();
    }

    return failed(this).build();
  }
}
