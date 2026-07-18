# Sentinel Alert

budeme opravovat, optimalizovat, vylepsovat a vyvijet 

PRAVIDLA
0. ptej se kdyz si nebudes jisty
1. ssh klic pro overovani na hostech je v /home/foxik/ssh-key
2. analyzuj celou slozku, udelej si poradny prehled
3. najdi problemy a navrhni reseni
5. navrhy na dalsi monitoring co tools
6. nechci aby se hlasili tmux root, ciste jen root prihlaseni a z jake ip
7. chci moznost ignorovat root z danych IP
8. zarizeni muze mit vice IP, duplikuji se tak hlaseni (ethernet a wifi, ci 2x ethernet...)
9. hlasi problemy se service, ale po kontrole vsechny service bezi, vicenasobna detekce nez to nahlasi
10. pokud se zmeni detekovane issue na resolved, je treba o tom informovat i Sentinel ! at tam nevisi vyresene veci
11. kdyz service agenta bezi, potrebuji nejak moznost na serveru kde bezi se doptat na aktivni issue -> priklad jsem na rpi, zavolam agent_issues a vrati se mi seznam aktivnich issue i s popisem

---

## Guidelines for Behavior (Strict)

### 1. Think before you code
- Don't assume. If you're not sure, stop and ask.
- Explicitly emphasize trade-offs.
- If there are multiple interpretations, present them - don't silently choose.

### 2. Simplicity First
- Minimal code that solves the problem. No speculative functions.
- No abstractions for disposable code.
- "Would the lead engineer say this is too complicated?" If so, rewrite.

### 3. Surgical Changes
- Touch only what is necessary.
- Do not improve or refactor existing code unless it is an explicit task.
- Adapt existing style.
- Every changed line must directly reference the requirement.

### 4. Goal-Oriented Execution
- Before coding, provide a plan:
1. [Step] → verify: [check]
2. [Step] → verify: [check]
- Before implementing, write tests/checks that reproduce the goal.

---

**These guidelines work if:** fewer unnecessary changes, fewer reworked solutions, and questions come *before* implementation.
