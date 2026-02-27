Password Strength Checker (x86 Assembly)

This program is a 16-bit DOS application written in x86 Assembly that reads a password using masked input and evaluates its security level based on specific complexity rules.
Project Overview

The application ensures security by masking keystrokes with asterisks (*) and requiring a two-step "Enter + Confirm" process. It enforces strict input rules to prevent common errors before analyzing the final strength of the password.
Features

    Masked Input: Prints * for each character typed to maintain privacy.

    Input Validation: * Prohibits spaces (immediate invalidation).

        Prevents empty password submissions.

        Ensures both entered passwords match exactly.

    Automated Retries: Repeats the prompt until a valid, matching pair is provided.

    Strength Analysis: Provides a YES/NO checklist for the following criteria:

        Length ≥8 

        Presence of uppercase letters 

        Presence of lowercase letters 

        Presence of digits 

        Presence of special characters 

Technical Details
Memory Layout

The program uses a structured data segment to manage buffers and state:

    Constants: MAXLEN is set to 30 characters.

    Buffers: Two 30-byte buffers (pw1 and pw2) store the password attempts.

    Flags: Individual bytes track the presence of required character types and the final score (0–5).

Logic Flow

    ClearBuffers: Resets the memory space using rep stosb.

    ReadPasswordMasked: Captures characters via INT 21h, AH=08h (no echo) and handles backspaces or illegal spaces.

    AnalyzePassword: Checks the buffer against ASCII ranges for 'A'-'Z', 'a'-'z', and '0'-'9'.

    PrintStrength: Uses the calculated score to display one of three results:

        WEAK

        MEDIUM

        STRONG

How to Run

    Assemble the source code using an assembler like MASM or TASM.

    Link the object file to create an executable (.EXE).

    Run the program in a DOS environment or an emulator like DOSBox.