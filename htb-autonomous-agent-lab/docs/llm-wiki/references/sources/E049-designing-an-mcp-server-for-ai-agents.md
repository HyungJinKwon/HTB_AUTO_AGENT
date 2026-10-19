<!-- source: https://specterops.io/blog/2026/07/28/designing-an-mcp-server-for-ai-agents-bloodhound-hunter/
     fetched_from: https://specterops.io/blog/2026/07/28/designing-an-mcp-server-for-ai-agents-bloodhound-hunter/
     retrieved: 2026-10-19
     raw_sha256: 2db9743fa07d484b4a815adab8d94a067608a8c4c3416b6af3e8fae9358cb3b0
     note: text extraction of the original page; formatting simplified -->

Designing an MCP Server for AI Agents | SpecterOps

  NEW! On-demand training built around real-world adversary tactics. Learn more  <https://academy.specterops.io/>

    Back to Blog

 AI & Security <https://specterops.io/blog/category/ai-security/>

# Designing an MCP Server for AI Agents: Why Wrapping Your API Is the Wrong Abstraction

Author

 Kaleb Pomeroy <https://specterops.io/blog/author/kpomeroy/>

Read Time

12 mins

Published

Jul 28, 2026

##### Share
    <https://www.linkedin.com/shareArticle?mini=true&url=https%3A%2F%2Fspecterops.io%2Fblog%2F2026%2F07%2F28%2Fdesigning-an-mcp-server-for-ai-agents-bloodhound-hunter%2F&title=Designing+an+MCP+Server+for+AI+Agents%3A+Why+Wrapping+Your+API+Is+the+Wrong+Abstraction&source=SpecterOps>    <https://twitter.com/share?url=https%3A%2F%2Fspecterops.io%2Fblog%2F2026%2F07%2F28%2Fdesigning-an-mcp-server-for-ai-agents-bloodhound-hunter%2F&text=Designing+an+MCP+Server+for+AI+Agents%3A+Why+Wrapping+Your+API+Is+the+Wrong+Abstraction>       <https://specterops.io/blog/category/ai-security/feed/>

Put Insights Into Action

-   Explore our Platform   <https://specterops.io/platform/bloodhound-enterprise/>

-   Explore Services   <https://specterops.io/services/>

An MCP server for AI agents is not just a wrapper around your existing REST API. The tools have to be shaped around agent intent rather than backend implementation. This post explains why wrapping your API is the wrong abstraction and how to design MCP tools that guide a security engineer, defender, or red-teamer’s agent through real workflows.

Key takeaways

- An MCP server for AI agents should be designed around agent intent, not by wrapping existing API endpoints.

- AI agents are a new kind of user: unlike traditional API clients, they begin with exploration and need to orient themselves before acting.

- APIs can be implementation-shaped because their callers already know what they want; MCP tools should be intention-shaped because the agent is still deciding what to do.

- Good MCP design applies decades-old interface principles: reduce cognitive load, hide complexity, organize around workflows, and guide the user.

- If a user or agent has to leave the interface and reconstruct product knowledge, the interface is incomplete.

## With AI, assume nothing

Part of my role in Ghostworks <https://specterops.io/blog/2026/06/09/introducing-ghostworks-ai-cybersecurity-research/> is to explore what AI means for BloodHound. When I ended the conversation above, I thought I knew what it was supposed to look like. We already had a mature REST API. Every feature in the product eventually mapped to one or more endpoints. Building an MCP server felt mechanical: expose those endpoints, give them good descriptions, and let the model figure out the rest. This felt flat, but I couldn’t articulate why. I didn’t want to build this at all.

Across different implementations and experiments with Codex, I saw a consistent thread. What was off wasn’t because of a protocol limitation, interchange formats or an LLM hallucination. It was because we kept asking a surprisingly simple question while watching the OpenAI agent use our tools: What tool is the agent supposed to use?

Not what tool can it use. What tool should it use.

That distinction ended up changing almost every design decision we had made.

Our API has grown over years. New things have added. Existing workflows evolved. Features accumulated. Some endpoints existed because they made one view faster. Others because a customer asked for a slightly different perspective. Some are there because changing them would have broken an old workflow.

Every endpoint, undocumented feature, and switch has a reason to exist. But the agent doesn’t care.

It isn’t trying to understand our implementation. It isn’t trying to navigate the history of our engineering decisions. It has a goal.

“Help me investigate this finding.”

The more we looked at the problem through that lens, the more obvious it became that wrapping the API was the wrong abstraction. The issue was not that the agent needed access to every capability BloodHound had. The issue was that it needed to understand what to do next.

At first, that made the MCP server very small. We removed tools. We combined others. We hid implementation details that suddenly felt like noise instead of capability. That felt backwards. Weren’t we supposed to expose more of the product to AI? But every simplification made the interface easier to use.

In a recent blog post <https://tengli.dev/posts/mcp-servers-failing-agents.html>, machine learning engineer Teng Li described the problem: “The Model Context Protocol spec tells you how to transport tools: JSON-RPC framing, capability negotiation, schema shapes. It says nothing about whether a model can actually use what you serve.”

To get to the right solution, we had to change our understanding of the problem. More importantly, we had to rethink for whom we were solving the problem.

## AI Agents Are a New Kind of User

For decades, we’ve built software for two different kinds of consumers.

The first is humans. We build websites, desktop applications, mobile apps, command line interfaces, and dashboards. We think about navigation, discoverability, progressive disclosure, sensible defaults, and reducing cognitive load. None of those things change what the software is capable of. They change how easily someone can accomplish what they came to do.

The second is software. REST, GraphQL, gRPC, SQL, message queues; these aren’t really user interfaces at all. They’re contracts between deterministic systems. The caller already knows what it wants. When a service calls GET /findings, it already knows findings exist. It knows how to authenticate. It knows the schema. It knows what it expects back. There is no exploration happening. There is only execution.

AI agents don’t fit neatly into either category. They’re not humans, but they’re not traditional API clients either. Agents often start with exploration. Much like a human scanning a website visually to orient, we need to give the agents a way to orient themselves in a way traditional software usually doesn’t need to do.

That’s why the question “What tool should the agent use?” kept coming up. Rather than looking for an endpoint, the agent was trying to learn the application.

That shift in perspective changed how we thought about the whole MCP server. Instead of asking which API endpoints deserved a tool, we started asking what the agent was actually trying to accomplish. Once we started designing around intent instead of implementation, a lot of the protocol suddenly made more sense.

By creating a small remediation index, resources became an agentic navigation mechanic; the agent could see the structure without pulling unnecessary context. Prompts started feeling more like CSS than boilerplate instructions. A webpage works perfectly well without CSS, but it guides the experience, nudges attention and gives structure. The underlying page remains the same. Prompts did the same thing for the agent, guiding its approach.

Even tool design became simpler. The right question wasn’t “What functionality should exist?” It became “If I were trying to accomplish this task, what would I want to discover next?” That’s interface design, not systems design. And the principles that make it work aren’t new.

- Help users reduce cognitive load.

- Hide unnecessary complexity.

- Organize around workflows instead of implementation details.

- Guide the user instead of exposing everything.

We’ve been learning those lessons for decades. The only thing that’s changed is who the user is. For the first time in a long time, it’s forcing us to think seriously about interface design again, this time for something between a person and a deterministic system.

By the end of this pass, we reduced the API surface to a couple of simple calls. The API was tight, the agent could answer with clarity and accuracy across a range of test datasets. For the one task we set out to do.

## Rebuilding the MCP Server Around Agent Intent

See BloodHound Hunter in action.
Once we made the MCP server as small as it could be, we started adding things back.

That sounds like it contradicts everything I just said. It doesn’t.

Before, we were adding tools because BloodHound had functionality. Every missing tool made the server look like an incomplete API wrapper. Chasing feature parity with the API felt tedious and unhelpful, and the agent using it was equally unsure what it was supposed to do.

Once the server was organized around a workflow, missing tools became much easier to reason about. We could watch the agent try to investigate something and ask UX questions.

- Why is the user doing it that way?

- When does the user use the wrong tools or misunderstand the intent?

- Which tools is the agent using incorrectly or unsuccessfully?

- Where is it reconstructing product knowledge it doesn’t need?

### When the Agent Leaves the Interface: The Export URL Tool

Sometimes the answer was obvious, like when the agent wants to reach for tools outside the MCP server.

A good example was Explore links. If the agent finds an interesting path it wants to share with the user, of course it can probably construct a URL itself. It can learn the route. It can encode the query. It can figure out how selected items are represented. It can escape values. It can carry around UI-specific assumptions until something changes.

But why should it? Constructing that URL by hand means reverse engineering our product, not reasoning. So we added a tool for it.

Not because “create Explore URL” was an important API endpoint. It wasn’t. We added it because the agent had crossed an interface boundary. It had the right intent: “show this path to the user in BloodHound.” The product should own the translation from that intent into a safe, valid, reusable link. (bonus, saves on token use over defining a skill for this)

That became one of the rules we kept coming back to:

If the user has to leave the interface and reconstruct product knowledge, the interface is incomplete.

### Bounding Raw Queries: Cypher as an Escape Hatch

Other times, the agent was technically using the right tool, but using it too broadly.

Cypher was the clearest example. A model that can write graph queries will reach for graph queries. That’s useful, but it is also a ton of expertise in writing these queries. Most questions are not really “run arbitrary Cypher.” They’re often more specific and limited:

- “Who controls this object?”

- “What can this principal reach?”

- “What are this object’s neighbors?”

- “Is there a path between these two things?”

Those are graph questions, but they are not the same interface. A raw query gives the agent power. A semantic tool gives it direction.

So Cypher stayed, but it became the escape hatch: read-only, bounded, and explicitly not the first choice. Around it we added more opinionated graph tools: object lookup, neighborhood expansion, reachability, summaries, attack paths, and capability discovery.

The point was to make the common safe path easier than the powerful vague one, not to remove flexibility.

### Using MCP Prompts to Guide Agent Workflows

And sometimes the agent didn’t need another tool at all. It needed instruction.

Prompts started to make more sense here, less as magic or a way to make the model smarter, but as workflow affordances. If a human analyst knows to triage first, inspect bounded evidence second, retrieve remediation guidance third, and only export bulk data when necessary, we should not expect the agent to rediscover that ordering every time.

The best prompts are not stringing a complicated sequence of steps together (see the export URL above). The prompts are to explain, guide and direct attention to the parts of the application that matter in the context of the problem the user is trying to solve.

## One API, Many Interfaces: Intention-Shaped vs. Implementation-Shaped Tools

In a normal product, one backend API can support many parts of the UI. The same endpoint or two might back a table, a graph, an entity panel, a filter menu, and an export button. That’s fine because the UI already knows which experience it is building.

An agent does not.

APIs are allowed to be implementation-shaped because their callers already know what they are doing. MCP tools should be intention-shaped. The user decides what to do, and the MCP server should help them decide. We stopped decomposing BloodHound by backend capability. We started decomposing it by the decisions an agent needed to make.

By the end, BloodHound Hunter had more lines of code than the naive API-to-MCP approach we started with.

But it got bigger in a way I didn’t initially expect. We were adding user interfaces, not endpoints or even more functionality. The goal of an MCP server is to make the right next action obvious, not to expose everything the product can do.

The best interface is not the one with the most capability. It is the one that removes enough ambiguity that the user, human or agent, can move through the space with confidence and accuracy.

  Post Views: 8,052

  Kaleb Pomeroy  <https://specterops.io/blog/author/kpomeroy/>
 Software Engineer

Kaleb Pomeroy is a software engineer at SpecterOps researching agentic systems, memory architectures, and interaction design. His work focuses on bridging modern AI research with practical software engineering.

##  Ready to get started?

     Book a Demo     <https://specterops.io/get-a-demo/>

### You might also be interested in

Research & Tradecraft

## ConnectWise SkyKick Breach: How to Check Your Microsoft 365 Tenant

 Last updated October 17, 2026 An attacker used a compromised credential belonging to ConnectWise Cloud Backup (formerly SkyKick) to sign…

By: Justin Kohler, Duane Michael

5 mins

  <https://specterops.io/blog/2026/10/17/connectwise-skykick-breach-microsoft-365/>

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