<!-- source: https://specterops.io/blog/2026/09/22/introducing-ghostwriter-skills/
     fetched_from: https://specterops.io/blog/2026/09/22/introducing-ghostwriter-skills/
     retrieved: 2026-10-19
     raw_sha256: 6e5f80c22f1e4a65181527bdc95ceb67154258233495284da8bcff68c62d6e30
     note: text extraction of the original page; formatting simplified -->

Introducing Ghostwriter Skills - SpecterOps

  NEW! On-demand training built around real-world adversary tactics. Learn more  <https://academy.specterops.io/>

    Back to Blog

 AI & Security <https://specterops.io/blog/category/ai-security/>

# Introducing Ghostwriter Skills

Author

 Christopher Maddalena <https://specterops.io/blog/author/christophermaddalena/>

Read Time

8 mins

Published

Sep 22, 2026

##### Share
    <https://www.linkedin.com/shareArticle?mini=true&url=https%3A%2F%2Fspecterops.io%2Fblog%2F2026%2F09%2F22%2Fintroducing-ghostwriter-skills%2F&title=Introducing+Ghostwriter+Skills&source=SpecterOps>    <https://twitter.com/share?url=https%3A%2F%2Fspecterops.io%2Fblog%2F2026%2F09%2F22%2Fintroducing-ghostwriter-skills%2F&text=Introducing+Ghostwriter+Skills>       <https://specterops.io/blog/category/ai-security/feed/>

Put Insights Into Action

-   Explore our Platform   <https://specterops.io/platform/bloodhound-enterprise/>

-   Explore Services   <https://specterops.io/services/>

TL;DR: Ghostwriter Skills is a new collection of portable Agent Skills for common Ghostwriter workflows. The initial release includes skills for creating and reviewing report templates, checking whether a report is ready for final reporting steps, and drafting an executive summary from an existing Ghostwriter report.

### Introduction

We recently introduced SpecterOps Skills <https://specterops.io/blog/2026/09/02/specterops-skills/>, our public repository for turning practitioner knowledge into reusable, reviewable workflows for AI agents.

Today, we’re extending that idea to Ghostwriter.

Ghostwriter Skills <https://github.com/GhostManager/ghostwriter-skills> is a new collection of portable Agent Skills built around common Ghostwriter workflows. The initial release focuses on a few areas where there are well-defined, repeatable processes that can benefit from additional automation: creating report templates, reviewing templates, checking a project’s report readiness, and helping authors get started on an executive summary.

This work comes out of our broader GhostWorks <https://specterops.io/blog/2026/06/09/introducing-ghostworks-ai-cybersecurity-research/> initiative, where we have been experimenting with ways to make agent workflows useful to security practitioners without tying them to a particular model or provider.

For Ghostwriter, the goal is straightforward: package some of the knowledge required to complete common tasks so users can spend less time figuring out the mechanics and more time on the more valuable human analysis aspects of an assessment. This is the first collection of Ghostwriter-specific skills, and we plan to continue expanding it with more reusable workflows.

This initial release includes skills for:

- Converting a sample report into a template

- Running linting and compatibility checks on a template

- Reviewing a project for report readiness near the end of an assessment

- Drafting an executive summary based on a report’s findings and other fields

Read on for a more detailed look at each of these skills.

## Creating Ghostwriter Templates

Building a new Ghostwriter report template often starts with something you already have, like a sample report or an existing template that contains the layout, branding, and styles you want to carry over. Turning that document into a reusable Ghostwriter Jinja2 template can require a fair amount of manual work. It can also be an intimidating task for people who are new to Ghostwriter or Jinja2.

The create-template skill helps with that conversion. Give it a report document and the skill analyzes it to identify content that can be replaced with Ghostwriter variables, loops, or fields while preserving the existing document structure wherever possible.

Creating a template involves more than simply replacing text. Reports typically contain section breaks, tables of contents, headers and footers, images, and formatting. The skill considers those elements when building the new template and calls out anything it cannot map confidently.

The result is a converted template plus a report describing the mappings, proposed extra fields, and areas that may still need review. The new template and accompanying conversion report will include suggestions for custom fields you can create in Ghostwriter to hold your content. For example, if it finds an Executive Summary section, the skill will suggest replacing it with a matching custom field. If you provide a live Ghostwriter instance and a service token, the skill will check your instance’s extra field spec and suggest a field from your existing fields.

The skill works with any document the LLM can read, but you get the best results when you provide a Word DOCX file. The skill will clone the DOCX document’s styling and any included images (e.g., your company logo) and produce an accurate DOCX template. It will do its best to recreate elements when analyzing a file like a PDF report.

For organizations with established report formats, this can substantially reduce the work required to bring a new template into Ghostwriter.

## Reviewing Templates

The companion review-template skill focuses on template QA. A DOCX or PPTX can look correct in Office while still containing problems that affect Ghostwriter rendering. Jinja syntax is the most common stumbling block for a new template, and it’s hard to identify these issues with a manual review. Styles, bookmarks, relationships, page breaks, and other Word fields also all matter and can cause problems that are often invisible until you’re trying to finalize the template. Sometimes these issues are not apparent until you have a final report and are trying to create a PDF or update fields for the final report.

The skill checks for the Ghostwriter compatibility issues it can reproduce offline and supplements those checks with broader document analysis.

For Word templates, that can include things like broken references, suspicious external dependencies, problematic Jinja placement, missing styles, table or numbering issues, and other conditions that may produce unexpected output down the line.

For PowerPoint templates, it can inspect layouts, placeholders, inheritance, and common presentation-template problems.

It can also review a template against an organization’s style guide or approved reference template, keeping Ghostwriter compatibility separate from broader presentation or authoring recommendations.

That all makes the skill useful both when developing a new template and when troubleshooting an existing one. You can even run it against your current templates and you might be surprised at the results.

## A Ready Check Before Final Reporting

The report-readiness skill helps with determining whether or not a project is ready to move into its reporting workflow.

The skill takes a Ghostwriter project ID and then evaluates it to flag issues such as incomplete findings, unresolved project objectives, missing essential content, placeholders, CVSS inconsistencies, or expected BloodHound data that is not present.

Instead of producing a simple pass/fail result, it separates findings into blockers, warnings, passed checks, and items it could not assess. The skill prioritizes the results in a list of things to review or correct.

This gives report authors and reviewers another way to catch mechanical or completeness issues before spending time on final editing and delivery. For example, the skill will flag an objective still marked as in progress rather than missed or achieved. Operators can review the objective and update its status so an incorrect status does not leak into the final report to be flagged during a QA pass.

## An Executive Summary Starting Point

The final skill in the initial collection is draft-executive-summary. This is an area Ghostwriter users have asked us about, and it is also an area where we want to be deliberate.

The skill accepts one Ghostwriter report or project ID and reviews its linked findings to produce a draft executive summary grounded in the information already present in the report. It can also incorporate other content and fields, such as an attack path narrative, when one exists.

The intent is to provide a starting point for the report author, not to hand report writing over to a language model.

Executive summaries require judgment about what matters, how technical findings relate to business risk, what context is important to the client, and how the assessment should ultimately be communicated. Those decisions still belong to the person responsible for the report.

The skill helps organize the source material and produce a first draft that an author can review, rewrite, or discard as appropriate.

### Offline or Connected Modes

Most of the skills support an “offline mode” wherever practical. Each skill in this repository will try to use a live Ghostwriter instance whenever it makes sense. You can provide a project-read service token, the address of your Ghostwriter instance, and a project or report ID and the skills will pull relevant information from the live instance.

Template creation and review can operate directly on local DOCX and PPTX files. Report readiness and executive-summary drafting can work from complete Ghostwriter report data exports.

When live Ghostwriter context is useful, the skills can switch to using the Ghostwriter GraphQL API endpoint with the provided project-read service token. That gives users flexibility in how they incorporate the skills into their environment without making a live Ghostwriter connection a requirement for every workflow. Using the project-read service tokens means using the skills will never lead to the LLM altering any data in Ghostwriter.

## Making Portable Skills

Ghostwriter Skills is maintained separately from the Ghostwriter application itself and is versioned independently.

The collection is designed to remain portable across Agent Skills-compatible tools such as Claude Code, Codex, Cursor, GitHub Copilot, and others.

You can install the collection with the skills CLI <https://www.skills.sh>: npx skills add GhostManager/ghostwriter-skills

That portability is an important part of the project. We want the useful part of these workflows to be the Ghostwriter and practitioner knowledge they capture rather than assumptions about whichever model or agent happens to be executing them.

## Wrap Up

This is the first Ghostwriter Skills release, and we plan to keep building on it.

The initial collection gives Ghostwriter users new ways to create templates from existing reports, review templates before use, run a structured readiness check, and get a starting point for an executive summary.

As with Ghostwriter itself, we expect the most useful additions to come from real workflows and community feedback.

You can find Ghostwriter Skills on GitHub <https://github.com/GhostManager/ghostwriter-skills>, try the initial collection, and let us know what Ghostwriter workflows you would like to see us tackle next.

  Post Views: 4,458

  Christopher Maddalena  <https://specterops.io/blog/author/christophermaddalena/>
 Director of Internal and Community Projects

Christopher Maddalena is the Director of Internal and Community Projects at SpecterOps with over 20 years of experience in technology and a decade focused on offensive security. He leads and maintains open source initiatives such as Ghostwriter, supports the security community through conference involvement and education, and previously led red team operations for Fortune 100 and 500 organizations.

##  Ready to get started?

     Book a Demo     <https://specterops.io/get-a-demo/>

### You might also be interested in

Research & Tradecraft

## Be the Architect: Intentional AI Engagement for Cybersecurity Engineering

 TL;DR: How SpecterOps combined deliberate human engagement, model routing, and specialized tools to overhaul Ghostwriter’s user interface for $815.50 in…

By: Christopher Maddalena

20 mins

  <https://specterops.io/blog/2026/10/14/ai-engagement-for-cybersecurity-engineering/>

Industry Insights

## What the 2026 Microsoft Digital Defense Report reveals about AI, identity, and the future of cybersecurity

 Key Takeaways The recently released 2026 Microsoft Digital Defense Report describes a security landscape shaped by interconnected risk, identity sprawl,…

By: Justin Kohler

9 mins

  <https://specterops.io/blog/2026/10/08/what-the-2026-microsoft-digital-defense-report-reveals-about-ai-identity-and-the-future-of-cybersecurity/>

AI & Security

## Introducing Adversary Intelligence: LLM Tradecraft

 TL;DR: Adversary Intelligence: LLM Tradecraft is a new on-demand course covering how modern LLMs and agentic systems work, how they…

By: Will Schroeder

7 mins

  <https://specterops.io/blog/2026/09/30/introducing-adversary-intelligence-llm-tradecraft/>