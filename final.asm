; Password Strength Checker (emu8086, 8086)
; - Masked input (prints '*' for each char)
; - Confirm password (type twice)
; - Spaces are NOT allowed (invalid)
; - Repeats until user enters a valid + matching password
; - Then shows checklist (YES/NO) + Weak/Medium/Strong

org 100h
jmp start

MAXLEN equ 30

prompt1     db 13,10,"Enter password: $"
prompt2     db 13,10,"Confirm password: $"

nl          db 13,10,"$"

errMismatch db 13,10,"Passwords do not match. Try again.$"
errSpace    db 13,10,"INVALID: spaces are not allowed. Try again.$"
errEmpty    db 13,10,"Password cannot be empty. Try again.$"

lineLen     db 13,10,"Length >= 8:     $"
lineUp      db 13,10,"Has uppercase:    $"
lineLow     db 13,10,"Has lowercase:    $"
lineDig     db 13,10,"Has digit:        $"
lineSpec    db 13,10,"Has special:      $"

yesTxt      db "YES$"
noTxt       db "NO$"

msgWeak     db 13,10,13,10,"Result: WEAK$"
msgMed      db 13,10,13,10,"Result: MEDIUM$"
msgStrong   db 13,10,13,10,"Result: STRONG$"

pw1         db MAXLEN dup(0)
pw2         db MAXLEN dup(0)
len1        db 0
len2        db 0

hasUpper    db 0
hasLower    db 0
hasDigit    db 0
hasSpecial  db 0
lenOK       db 0
score       db 0

start:
main_loop:
    call ClearBuffers

    mov dx, offset prompt1
    mov ah, 09h
    int 21h

    lea di, pw1
    call ReadPasswordMasked

    cmp ah, 1
    je  bad_space

    mov [len1], al
    cmp al, 0
    je  bad_empty

    mov dx, offset prompt2
    mov ah, 09h
    int 21h

    lea di, pw2
    call ReadPasswordMasked
    cmp ah, 1
    je  bad_space

    mov [len2], al
    cmp al, 0
    je  bad_empty

    mov al, [len1]
    cmp al, [len2]
    jne bad_mismatch

    mov cl, [len1]
    xor ch, ch
    lea si, pw1
    lea di, pw2
cmp_loop:
    mov al, [si]
    cmp al, [di]
    jne bad_mismatch
    inc si
    inc di
    loop cmp_loop

    call AnalyzePassword
    call PrintChecklist
    call PrintStrength
    jmp quit

bad_space:
    mov dx, offset errSpace
    mov ah, 09h
    int 21h
    jmp main_loop

bad_empty:
    mov dx, offset errEmpty
    mov ah, 09h
    int 21h
    jmp main_loop

bad_mismatch:
    mov dx, offset errMismatch
    mov ah, 09h
    int 21h
    jmp main_loop

quit:
    mov dx, offset nl
    mov ah, 09h
    int 21h
    mov ax, 4C00h
    int 21h

ClearBuffers proc
    push ax
    push cx
    push di

    lea di, pw1
    mov cx, MAXLEN
    xor al, al
    rep stosb

    lea di, pw2
    mov cx, MAXLEN
    xor al, al
    rep stosb

    pop di
    pop cx
    pop ax
    ret
ClearBuffers endp


ReadPasswordMasked proc
    push bx
    xor bx, bx          
    xor ah, ah         

rp_read:
    mov ah, 08h
    int 21h            

    cmp al, 13         
    je  rp_done

    cmp al, 8         
    je  rp_backspace

    cmp al, ' '         
    jne rp_normal

    mov ah, 1         
flush_loop:
    mov ah, 08h
    int 21h
    cmp al, 13
    jne flush_loop
    jmp rp_done

rp_normal:
    cmp al, 0
    je  rp_read

    cmp bx, MAXLEN
    jae rp_beep

    mov [di], al
    inc di
    inc bx

    mov dl, '*'
    mov ah, 02h
    int 21h

    jmp rp_read

rp_backspace:
    cmp bx, 0
    je  rp_read
    dec bx
    dec di
    mov byte ptr [di], 0

    mov dl, 8
    mov ah, 02h
    int 21h
    mov dl, ' '
    mov ah, 02h
    int 21h
    mov dl, 8
    mov ah, 02h
    int 21h
    jmp rp_read

rp_beep:
    mov dl, 7
    mov ah, 02h
    int 21h
    jmp rp_read

rp_done:

    mov dl, 13
    mov ah, 02h
    int 21h
    mov dl, 10
    mov ah, 02h
    int 21h

    mov al, bl    
    pop bx
    ret
ReadPasswordMasked endp                            

AnalyzePassword proc
    mov byte ptr [hasUpper], 0
    mov byte ptr [hasLower], 0
    mov byte ptr [hasDigit], 0
    mov byte ptr [hasSpecial], 0
    mov byte ptr [lenOK], 0
    mov byte ptr [score], 0

    mov al, [len1]
    cmp al, 8
    jb  ap_len_done
    mov byte ptr [lenOK], 1
ap_len_done:

    lea si, pw1
    mov cl, [len1]
    xor ch, ch

ap_loop:
    mov al, [si]
    inc si

    cmp al, 'A'
    jb  ap_lower
    cmp al, 'Z'
    ja  ap_lower
    mov byte ptr [hasUpper], 1
    jmp short ap_next

ap_lower:
    cmp al, 'a'
    jb  ap_digit
    cmp al, 'z'
    ja  ap_digit
    mov byte ptr [hasLower], 1
    jmp short ap_next

ap_digit:
    cmp al, '0'
    jb  ap_special
    cmp al, '9'
    ja  ap_special
    mov byte ptr [hasDigit], 1
    jmp short ap_next

ap_special:
    mov byte ptr [hasSpecial], 1

ap_next:
    loop ap_loop

    cmp byte ptr [lenOK], 1
    jne ap_s1
    inc byte ptr [score]
ap_s1:
    cmp byte ptr [hasUpper], 1
    jne ap_s2
    inc byte ptr [score]
ap_s2:
    cmp byte ptr [hasLower], 1
    jne ap_s3
    inc byte ptr [score]
ap_s3:
    cmp byte ptr [hasDigit], 1
    jne ap_s4
    inc byte ptr [score]
ap_s4:
    cmp byte ptr [hasSpecial], 1
    jne ap_s5
    inc byte ptr [score]
ap_s5:
    ret
AnalyzePassword endp                                     

PrintChecklist proc
    mov dx, offset lineLen
    mov ah, 09h
    int 21h
    mov al, [lenOK]
    call PrintYesNo

    mov dx, offset lineUp
    mov ah, 09h
    int 21h
    mov al, [hasUpper]
    call PrintYesNo

    mov dx, offset lineLow
    mov ah, 09h
    int 21h
    mov al, [hasLower]
    call PrintYesNo

    mov dx, offset lineDig
    mov ah, 09h
    int 21h
    mov al, [hasDigit]
    call PrintYesNo

    mov dx, offset lineSpec
    mov ah, 09h
    int 21h
    mov al, [hasSpecial]
    call PrintYesNo

    ret
PrintChecklist endp                                        

PrintStrength proc
    mov al, [score]
    cmp al, 5
    je  ps_strong
    cmp al, 3
    jb  ps_weak

ps_med:
    mov dx, offset msgMed
    mov ah, 09h
    int 21h
    ret

ps_weak:
    mov dx, offset msgWeak
    mov ah, 09h
    int 21h
    ret

ps_strong:
    mov dx, offset msgStrong
    mov ah, 09h
    int 21h
    ret
PrintStrength endp

PrintYesNo proc
    cmp al, 1
    jne pyn_no
    mov dx, offset yesTxt
    mov ah, 09h
    int 21h
    ret
pyn_no:
    mov dx, offset noTxt
    mov ah, 09h
    int 21h
    ret
PrintYesNo endp
