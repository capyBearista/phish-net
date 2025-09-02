Product Requirements Document: Phishing Email Detector (phish-net)

Author: Arjun Pramanik
Date: September 1, 2025
Version: 1.0

1. Introduction & Background

Phishing remains one of the most prevalent and effective vectors for cyberattacks, targeting individuals and organizations alike. While many users are becoming more aware, sophisticated attacks can be difficult to identify. Existing AI tools, such as general-purpose Large Language Models (LLMs), can assist in analysis, but they often require users to send potentially sensitive or confidential email content to third-party cloud services. This presents a significant privacy concern.

This document outlines an exploratory project by an undergraduate student seeking to gain practical experience in applying AI/ML concepts to the field of computer security. The goal is to develop a tool that addresses the need for a private, secure method of analyzing suspicious emails.

1. Project Goals & Objectives

    Primary Objective: To create a functional, local web application that analyzes email content and headers to identify indicators of phishing attacks.

    User-Facing Goal: To provide a non-technical user with a clear, actionable assessment of an email's risk, including a risk score and a list of specific red flags.

    Technical Goal: To successfully integrate a pre-trained LLM (either locally via Ollama or via a remote API) into a Python-based application for text analysis.

    Learning Goal: To serve as a practical project for developing skills in Python, prompt engineering, basic web development (e.g., Streamlit/Flask), and API integration.

2. User Persona & Stories

    Persona: A privacy-conscious individual (e.g., a student, remote worker, or small business owner) who has received a suspicious email and wants an automated "second opinion" without uploading the email's content to a public service.

    User Stories:

        As a user, I want to be able to copy and paste the full source of a suspicious email into the application.

        As a user, I want the application to analyze the email and provide me with a simple-to-understand risk score (e.g., from 1 to 10).

        As a user, I want to see a structured list of specific reasons (red flags) that contributed to the risk score, so I can understand the potential threat.

3. Scope & Features (Version 1.0 - MVP)

The initial version of the product will focus on core functionality.

    F-01: Text Input: The user interface will consist of a single, large text area where a user can paste the full source code of an email (including headers and body).

    F-02: LLM-Based Analysis: Upon submission, the application will send the input text to a pre-trained LLM using a carefully crafted prompt. The prompt will instruct the model to act as a cybersecurity analyst and identify phishing indicators.

    F-03: Structured Output: The application will parse the LLM's response and display the following to the user:

        A numerical "Phishing Risk Score".

        A bulleted list of "Identified Red Flags" found in the email (e.g., "Sense of urgency," "Mismatched sender address," "Suspicious link text").

    F-04: Local Model Support: The core architecture will be built to support a local LLM via Ollama to ensure user privacy is maintained as a primary feature.

Out of Scope for Version 1.0:

    Direct email client integration (e.g., Outlook/Gmail plugins).

    File upload functionality for .eml files.

    Live URL scanning or reputation checks.

    Analysis of attachments or images.

5. Non-Functional Requirements

    Privacy: The analysis of user-submitted content must be processed locally on the user's machine. No email data should be transmitted to external, third-party servers for analysis in the default configuration.

    Usability: The interface must be minimal and intuitive, requiring no special instructions for a user to perform an analysis.

    Performance: The analysis should be completed within a reasonable timeframe (e.g., 30 to 60 seconds) on consumer-grade hardware running a local LLM.

6. Assumptions & Constraints

    Assumption: The user is capable of accessing the "full source" or "original message" of an email from their email client.

    Constraint: The tool's effectiveness is entirely dependent on the analytical capabilities of the chosen pre-trained LLM and the quality of the prompt. The project does not involve training a new model.

    Constraint: The analysis is limited to the textual content provided. The tool cannot verify the authenticity of email senders via technical means (e.g., SPF/DKIM validation) in its initial version.