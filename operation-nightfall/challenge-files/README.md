# Operation Nightfall

**Category:** Web Exploitation  
**Difficulty:** Hard  
**Points:** 1000 (Dynamic)  
**Author:** KSR CTF Team

---

## Description

NovaCorp Technologies is one of India's fastest-growing fintech startups. Their internal **DevPortal** — used by engineers to manage deployments, monitor services, and access internal APIs — was recently migrated to a new microservice architecture.

As part of a routine security audit, you've been given the URL to their DevPortal. The scope is limited to the web application at the provided URL. Your objective is to gain access to the flag file stored on the internal infrastructure.

> *"The strongest walls often have the smallest cracks. Look where the developers got lazy."*

## Connection Info

```
URL: http://<CHALLENGE_HOST>:8080
```

## Hints

<details>
<summary>Hint 1 (Free)</summary>
The status page lets you filter services. What happens when you filter for something... unexpected?
</details>

<details>
<summary>Hint 2 (-50 points)</summary>
Nunjucks is a powerful templating engine. What if the filter isn't just a filter?
</details>

<details>
<summary>Hint 3 (-100 points)</summary>
The DevPortal connects to several internal services. Can you find their addresses?
</details>

<details>
<summary>Hint 4 (-150 points)</summary>
Some developers leave default credentials in HTML comments. And some internal APIs trust webhooks too much.
</details>

<details>
<summary>Hint 5 (-200 points)</summary>
node-serialize has a well-known CVE. Check CVE-2017-5941.
</details>

## Flag Format

```
flag{...}
```

## Files

No downloadable files — this is a black-box web challenge.
