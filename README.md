
# SAST SQL‑injection / “unsanitized external input in SQL query” finding. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/2-java/unsanitized-external-input-in-sql-query)

## 1. Understand the finding

- Identify the **source** (where external input enters), the **transforms** (validation, parsing, business logic), and the **sink** (where the SQL is executed). [docs.bearer](https://docs.bearer.com/reference/rules/python_lang_sql_injection/)
- Confirm that the rule maps to CWE‑89 (unsanitized input in SQL) so you’re evaluating it with the right mental model. [cve.scap.org](http://cve.scap.org.cn/cwe/CWE-89)

## 2. Trace data flow from source to sink

- Determine whether any part of the query string comes from user or externally controlled input: HTTP parameters, headers, body fields, cookies, environment variables, external systems, etc. [snyk](https://snyk.io/articles/sast-sql-injection/)
- Follow that data through intermediate variables and functions to see if it reaches the SQL execution call without being constrained or sanitized. [mend](https://www.mend.io/blog/sast-false-positives/)

## 3. Assess how the SQL text is built

- Check if the query is built via string concatenation or interpolation that mixes SQL syntax with data values, which is the high‑risk pattern. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/2-java/unsanitized-external-input-in-sql-query)
- Distinguish between:
  - Input controlling **values** only (e.g., `WHERE col = ?` with bound parameters), which is usually safe when properly parameterized.  
  - Input controlling **SQL structure** (e.g., columns, operators, ORDER BY clause, raw fragments), which can still lead to injection even with parameterized values. [docs.datadoghq](https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/php-security/sql-injection/)

## 4. Evaluate validation and sanitization

- Look for strong, positive validation (whitelists) that restricts input to a small, known set of safe values (for example, only “ASC” or “DESC,” or a fixed list of column names). [docs.datadoghq](https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/php-security/sql-injection/)
- If the only defense is generic escaping or weak validation (length, regex that still allows quotes/operators), treat the issue as real until proven otherwise. [docs.bearer](https://docs.bearer.com/reference/rules/python_lang_sql_injection/)

## 5. Decide: real issue vs. false positive

Use a simple rubric:

- **Treat as a real issue** if:  
  - Untrusted input can influence SQL structure or appear unescaped inside a query string, and  
  - There is no strong whitelist or proper parameterization at the sink. [owasp](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
- **Consider it a false positive** only if:  
  - The query text is entirely static, or  
  - External input is tightly validated to a small safe set and used only in ways that cannot change the query semantics meaningfully (for example, mapped via an internal enum), and  
  - All user‑controlled values are passed as bound parameters rather than injected into the SQL string. [mend](https://www.mend.io/blog/sast-false-positives/)

In either case, document your reasoning (sources, validation, and sink behavior) so future triage for similar findings is faster and more consistent. [snyk](https://snyk.io/articles/application-security/static-application-security-testing/)

# “unsanitized dynamic input in OS command” (CWE‑78)[docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-dynamic-input-in-os-command)

## 1. Clarify context and threat model

- Identify where the code runs (developer laptop, shared build agent, production host) and what identities/credentials it has (deploy keys, cloud roles, secrets). [veracode](https://www.veracode.com/security/dotnet/cwe-78)
- Decide who can influence inputs (only trusted engineers, contributors via PRs, external users via pipeline variables, etc.); in CI/CD this often determines if it is “just” misuse risk or full attacker‑controlled injection. [infisign](https://www.infisign.ai/blog/ci-cd-pipeline-security-best-practices)

## 2. Map source → transform → sink

- **Source:** List all dynamic inputs that can reach OS commands: environment variables, pipeline variables, command‑line arguments, config files, repo content, generated metadata. [docs.bearer](https://docs.bearer.com/reference/rules/javascript_lang_dynamic_os_command/)
- **Transform:** Check if the inputs are validated, normalized, or mapped to safe enums before use, or simply concatenated into a command string. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-user-input-in-os-command)
- **Sink:** Identify the exact call sites that execute commands (for example, `exec`, `spawn`, `system`, `Process.Start`, shell steps in pipelines) and how they construct their arguments. [veracode](https://www.veracode.com/security/dotnet/cwe-78/)

## 3. Analyze how commands are constructed

- Distinguish between APIs that take a single shell string (more dangerous) and those that pass program and argument list separately (safer when used correctly). [mathworks](https://www.mathworks.com/help/bugfinder/ref/cwe78.html)
- Look for patterns where variables are embedded directly into shell strings or backticks, especially if they can introduce metacharacters (`;`, `&&`, `|`, `$()`, backticks, `&`, newlines). [docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-dynamic-input-in-os-command)  

Example pattern to flag in any language: dynamic values inside a shell command string such that changing the value can add new arguments or operators, not just change data.

## 4. Decide: real issue or acceptable / false positive

Use a simple rubric for each finding:

- **Real issue (needs remediation)** if:  
  - Untrusted or semi‑trusted input can affect the command name, path, flags, or introduce shell metacharacters, and  
  - The command is executed via a shell or equivalent, with no strong whitelisting or argument separation. [docs.bearer](https://docs.bearer.com/reference/rules/go_gosec_injection_subproc_injection/)
- **Potentially acceptable / downgrade / suppress** if all are true:  
  - Input is from a strongly trusted and gated source (for example, internal deploy script invoked only by release engineers) and  
  - The variable is tightly constrained (mapped to a fixed set of values or paths, no shell metacharacters possible) and  
  - The command API separates executable and arguments, and inputs are only used as single arguments, not interpreted by a shell. [it.mathworks](https://it.mathworks.com/help/bugfinder/ref/cwe78.html)

Document that decision for each policy hit so you can be consistent across all pipeline scripts.

## 5. Preferred remediation patterns (especially for CI/CD scripts)

When a finding is real, your standard process should push toward these patterns:

- Prefer native APIs or library calls over shelling out at all (for example, Git/Cloud SDK libraries, CI built‑in steps) to avoid OS command construction entirely. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/2-java/unsanitized-user-input-in-os-command)
- When you must run commands:  
  - Use APIs that take `{program, [args...]}` instead of a single command string, and avoid a shell layer unless strictly necessary. [veracode](https://www.veracode.com/security/dotnet/cwe-78)
  - Restrict dynamic pieces to a whitelist (for example, recognized environments, branches, small set of subcommands) and reject or fail closed on anything else. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-dynamic-input-in-os-command)
  - Sanitize any remaining text inputs to strip/forbid metacharacters and unexpected whitespace; treat this as a last line of defense, not the primary control. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-user-input-in-os-command)

## 6. CI/CD‑specific review questions

For violations in deploy or pipeline scripts, add these checks:

- Can an attacker or low‑trust contributor influence the variables used in the command (for example, through PRs, pipeline parameters, variable groups)? [pulsesecurity.co](https://pulsesecurity.co.nz/advisories/Azure-Devops-Command-Injection)
- If the runner is compromised through command injection, what can it reach (secrets, registries, production clusters), and are runners segmented per environment? [cycode](https://cycode.com/blog/ci-cd-pipeline-security-best-practices/)

If the answer to those is “yes” and “a lot,” prioritize fixing the policy hit even if it is in “only” a script and not the main application.

Using this process, you can treat the “unsanitized dynamic input in OS command” policy as a consistent triage checklist across all your deploy and automation scripts, instead of handling each example ad hoc. [docs.bearer](https://docs.bearer.com/reference/rules/javascript_lang_dynamic_os_command/)

Here’s a Markdown **process** you can drop into docs and train on, with the generic “context” step removed.

***

# XXE SAST Triage Process  
_For “Unsanitized user input in XML External Entity” (CWE‑611)

## Step 1 – Map Source → Transform → Sink

1. **Identify sources (inputs)**  
   - List all inputs that influence the XML being loaded or parsed (HTTP body, query string, file upload, URL, headers, MQ messages, etc.). [docs.sec1](https://docs.sec1.io/user-docs/4-sast/2-java/unsanitized-user-input-in-xml-external-entity)
   - Mark which of these are user‑controlled or external.

2. **Review transforms (validation / mapping)**  
   - Check whether these inputs are:  
     - Mapped to a **whitelist** of allowed values (e.g., known file names, IDs), or  
     - Passed through directly as XML, XML path, or XML‑related parameters.  
   - Note any schema validation or strict format checks.

3. **Locate sinks (parsers)**  
   - Identify the XML parsing calls (DOM, SAX, StAX, framework XML helpers, etc.). [cwe.mitre](https://cwe.mitre.org/data/definitions/611.html)
   - Link each parser call to its upstream inputs from steps 1–2.

***

## Step 2 – Check Parser Configuration for XXE Defenses

For each XML parser instance found in Step 1:

1. **Look for explicit XXE hardening**  
   - Confirm that DTDs and external entities are **explicitly** disabled, using language‑appropriate flags/properties. [docs.bearer](https://docs.bearer.com/reference/rules/java_lang_xml_external_entity_vulnerability/)
   - Check resolver settings to ensure external DTD/schema/entity access is blocked or restricted.

2. **Flag risky defaults**  
   - If the parser is constructed with **default settings** and processes any user or external input from Step 1, mark it as **not hardened** for XXE. [owasp](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

***

## Step 3 – Decide: Fix vs. Downgrade vs. Accept (Per Finding)

Use this decision rubric:

- **Treat as a vulnerability (Fix)** when **all** apply:  
  - Untrusted or semi‑trusted input influences the XML content or what is loaded.
  - Parser configuration does **not** clearly disable external entities/DTDs.  
  - There is a real impact if XXE is exploited (e.g., file access, SSRF, DoS). [cvedetails](https://www.cvedetails.com/cwe-details/611/Improper-Restriction-of-XML-External-Entity-Reference.html)

- **Consider downgrade / accept with justification** only when **all** apply:  
  - Input is effectively trusted or constrained to a tight whitelist (no arbitrary XML). [feedly](https://feedly.com/cve/cwe/611)
  - Parser is explicitly hardened against XXE as in Step 2.  
  - Remaining risk is clearly non‑exploitable in that context (e.g., no meaningful external file/network access). [github](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

For every decision, record a **one‑sentence justification** (e.g., “User XML + default parser ⇒ fix” or “Whitelisted file + hardened parser ⇒ accepted risk”).

***

## Step 4 – Standard Remediation Checklist (When Fixing)

When the decision is “Fix,” apply this checklist:

1. **Harden the parser**  
   - Disable DTDs and external entity resolution for the XML parser/factory according to your language’s XXE guidance and OWASP cheatsheet. [github](https://github.com/nokia/OWASP-CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

2. **Constrain or change input format**  
   - Avoid accepting arbitrary XML when possible; prefer safer formats (e.g., JSON), or  
   - Map user inputs to **server‑side whitelisted** XML resources instead of using raw XML from users. [docs.sec1](https://docs.sec1.io/user-docs/4-sast/3-javascript/unsanitized-user-input-in-xml-parsing-method)

3. **Limit impact of any remaining XML parsing**  
   - Run parsing code with minimal filesystem/network privileges.  
   - Ensure no access to sensitive paths or internal endpoints that XXE could abuse. [jcarpizo.github](https://jcarpizo.github.io/owasp-info/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

Here’s a Markdown **process** you can train the team on for the “Invisible bidirectional and homoglyph Unicode characters” / Trojan Source–style policy (CWE‑506). [app.cycode](https://app.cycode.com/violations?f0=status&f0=Open&f1=risk_score_range&f1=risk_score_from%3D30&f1=risk_score_to%3D100&f1=include_null_risk_score%3Dtrue&f2=labels&f2=production&s=risk_score%2Cdesc&tenantId=ee7872ab-a58c-4a79-8485-a08d06b890e6&appsecModule=sast&ids=019aa0d0-d65d-7e59-a861-db50f5751b3a&showPartialPolicy=false&policyId=d20f5f00-7535-447a-b163-1744c384971b&groupBy=Policy&drawer=ZKE0DYH4pF&ZKE0DYH4pF_component=ViolationV2&ZKE0DYH4pF_id=07c6cc96-2b1c-4c38-9f24-5ac31688570b&ZKE0DYH4pF_ViolationV2_table=regular-policy-table)



