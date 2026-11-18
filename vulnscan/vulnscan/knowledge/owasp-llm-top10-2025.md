# OWASP Top 10 for LLM Applications (2025)

## LLM01:2025 Prompt Injection
User input (direct) or external content such as web pages, documents, emails and tool results (indirect) changes the model's behaviour, overriding its instructions.
Fix: constrain model behaviour in the system prompt but never rely on it alone; keep untrusted content separated and labelled; screen inputs with a classifier such as Llama Prompt Guard 2; validate outputs against an expected format; least-privilege tools; human approval for high-risk actions; regular adversarial testing.

## LLM02:2025 Sensitive Information Disclosure
The model reveals personal data, credentials, proprietary data or other users' data from its training data, context window or connected tools.
Fix: keep secrets out of prompts and context; sanitise and minimise data before it reaches the model; enforce access control on retrieval and tools per user; apply output filtering (DLP); be transparent about data use; avoid training on sensitive data.

## LLM03:2025 Supply Chain
Compromised or vulnerable third-party models, datasets, adapters (LoRA), libraries and model hubs; pickled model files that execute code on load; trust_remote_code.
Fix: vet model sources and pin revisions; prefer safetensors; scan model files (ModelScan); keep an AI-BOM/SBOM; scan ML libraries for CVEs; avoid trust_remote_code or review the code it runs.

## LLM04:2025 Data and Model Poisoning
Manipulated pre-training, fine-tuning or embedding data introduces backdoors, biases or hidden instructions.
Fix: track data provenance; validate and screen training and RAG data (including with an injection classifier); sandbox data ingestion; version datasets; red-team the model for backdoors; monitor for behaviour drift.

## LLM05:2025 Improper Output Handling
Model output is passed to downstream components without validation, leading to XSS, SQL injection, command execution, SSRF or path traversal.
Fix: treat the model like an untrusted user; encode output for its context (HTML, SQL, shell); use parameterised queries; never eval model output; apply a strict CSP; validate structured output against a schema.

## LLM06:2025 Excessive Agency
The model has more functionality, permissions or autonomy than needed (tools that can delete, pay or execute code), so a manipulated model causes real damage.
Fix: minimise tools and their permissions; run tools with the end user's identity and authorisation; require human approval for irreversible actions; log and rate-limit tool use; avoid open-ended tools like shells.

## LLM07:2025 System Prompt Leakage
The system prompt is extracted, exposing internal rules, credentials or architecture details that were assumed to be secret.
Fix: never put secrets, keys or authorisation logic in prompts; enforce security controls outside the model; assume the system prompt is public; monitor for prompt-echo in outputs.

## LLM08:2025 Vector and Embedding Weaknesses
RAG weaknesses: cross-tenant leakage through shared vector stores, poisoned documents that inject instructions, embedding inversion, missing access control on retrieved chunks.
Fix: permission-aware retrieval (filter by user/tenant); validate and classify documents before indexing; partition indexes per tenant; log retrievals; screen retrieved text for injection before adding it to the prompt.

## LLM09:2025 Misinformation
The model produces confident but false content, including hallucinated APIs and packages that attackers then register (package hallucination / slopsquatting).
Fix: ground answers with RAG and citations; verify package and command suggestions against registries; show uncertainty to users; human review for high-stakes output; automated evaluation for factuality.

## LLM10:2025 Unbounded Consumption
No limits on input size, output tokens, request rate or cost, enabling denial of service, denial of wallet and model extraction.
Fix: input-length caps; max output tokens; per-user rate limits and quotas; timeouts; cost monitoring and alerting; restrict logprobs and bulk access to deter model extraction.
