package com.myapp.auth.infrastructure.notification;

import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.domain.model.EmailAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.Duration;

/**
 * Sends the OTP over SMTP. Works with any free SMTP relay: Gmail (app password), Brevo, Amazon SES, Resend...
 * <p>
 * The email is plain text with no links, which avoids phishing-style "click here to log in" patterns
 * and keeps the code out of URLs, browser history and link-scanner logs.
 */
public final class SmtpOtpSender implements OtpSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpOtpSender.class);

    private final JavaMailSender mailSender;
    private final String from;
    private final String appName;

    public SmtpOtpSender(JavaMailSender mailSender, String from, String appName) {
        this.mailSender = mailSender;
        this.from = from;
        this.appName = appName;
    }

    @Override
    public void send(EmailAddress email, String code, Duration validFor) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email.value());
        message.setSubject(code + " is your " + appName + " sign-in code");
        message.setText("""
                Your %s sign-in code is: %s

                It expires in %d minutes and can be used once.

                If you didn't request this code, you can ignore this email. Never share this code with anyone.
                """.formatted(appName, code, validFor.toMinutes()));
        try {
            mailSender.send(message);
        } catch (MailException e) {
            log.error("Failed to send OTP email to {}", email, e);
            throw new IllegalStateException("Email delivery failed", e); // surfaces as generic 500
        }
    }
}
