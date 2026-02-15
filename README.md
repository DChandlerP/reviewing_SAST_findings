
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
