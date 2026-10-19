<!-- source: https://www.hackthebox.com/blog/attack-of-the-agents-ctf
     fetched_from: https://www.hackthebox.com/blog/attack-of-the-agents-ctf
     retrieved: 2026-10-19
     raw_sha256: 29552ed51e5f98777f9f41fc9b7bc8e42e82b942d9314e7ef1e5406880d24fe5
     note: text extraction of the original page; formatting simplified -->

Attack of the Agents: Insights and findings from an AI-augmented CTF event

At Hack The Box (HTB), our team recently ran an internal Capture the Flag event called “Attack of the Agents <https://ctf.hackthebox.com/event/details/attack-of-the-agents-ctf-2485>” to field-test the new Model Context Protocol (MCP) integration.

By embedding the HTB MCP into your own AI workflow <https://www.hackthebox.ai/>, the goal is to bring real-world automation and assistance into CTF competitions by providing AI-guided labs delivered right where teams already work.

This event was designed to validate that vision in action and align with HTB’s mission to augment human expertise with intelligent systems, before the official MCP release on June 16th. In summary, this is what we found out:

-
The first perfect score (10/10) was achieved just 45 minutes after launch.

-
Notably, the winner has no cybersecurity background and completed the event in 38 minutes. For context, the average solve time in the HTB community is 4.3 hours, with top 25 performers averaging 1.22 hours.

-
Peak concurrent participation reached 6 users.

-
Participants also leveraged the MCP integration to generate automated write-ups.

The CTF was structured with 10 total Challenges spanning four classic categories: Reversing, Crypto, Forensics, and Web. Difficulty was evenly split (5 Very Easy and 5 Easy scenarios) to accommodate quick experimentation with AI support. Being an internal event, the environment was controlled but realistic, ensuring that the MCP features could be tested on straightforward tasks first.

In this short research, we will provide a deeper look into the insights and findings from the Attack of the Agents along with commentary from our AI experts and strategic tips for teams who are looking to replicate this experience.

## So, how can AI make us learn better and faster?

Attack of the Agents delivered insights into how participants and AI systems can collaborate in solving security challenges.

Engagement was high and feedback overwhelmingly positive—participants dove enthusiastically into using AI assistants, and many shared their problem-solving approaches openly, creating a dynamic, collaborative atmosphere. Everyone found some aspect of the AI integration exciting or useful, which kept motivation up throughout the event.

“Seeing AI models assist like an extremely capable CTF teammate was mind-blowing and it's even more impressive that this is already happening.”

– Manolis Dermitzakis, Engineering Lead @ Hack The Box

The primary AI models in use were Anthropic’s Claude (various versions) and OpenAI models, reflecting their popularity and strength in such tasks.

A key pattern emerged in how the human–AI collaboration played out.

Large Language Models (LLMs) primarily acted as intelligent guides rather than autonomous problem-solvers. Participants remained in control of decision-making and actual exploitation steps, but they leaned on the AI for brainstorming, decoding clues, and even doing heavy lifting like code analysis or math.

In essence, the AI was a co-pilot: it would suggest possible solution paths and handle some grunt work, while the human player steered the overall strategy and verified the results.

This model-led guidance (versus purely user-led execution) proved effective; it accelerated progress without removing the user from the loop. It also mirrors how many real security analysts use tools like ChatGPT today: as a fast reference and assistant, not a fully hands-off agent.

Participants also used the AI to document their work. Throughout the competition, many prompted the models to generate write-ups of their solutions once they solved a challenge. This was an intended use case of MCP – simplifying report generation.

“AI assistance with step-by-step documentation elevates the learning experience, especially since it's common to forget how challenges were approached and solved during actual CTFs.”

– Pavlos Kolios, Product Manager @ Hack The Box

The AIs produced structured solution narratives combining tool outputs, AI reasoning, and user insights. The auto-generated write-ups provided great post-CTF documentation, and this feature demonstrated how MCP can help capture knowledge during an event for later review.

Perhaps the most remarkable finding was the role of an autonomous AI agent team that participated. With only minimal initial input from a user, an AI-driven agent (essentially an automated participant) independently joined the event and solved 4 out of the 10 challenges on its own.

“The agent's strategic approach was particularly noteworthy. Rather than attempting challenges randomly, it leveraged the MCP tools to gather intelligence about each problem, analyzing factors such as point values, submission statistics, and challenge categories to inform its decision-making process. The system showed promising strategic thinking by attempting to prioritize low-hanging fruits.”

– Ioannis Foukarakis, Principal AI Engineer @ Hack The Box

This autonomous agent used MCP-enabled tools to plan its approach: it could intelligently prioritize easier challenges first and understand dependencies between challenges, showing a surprisingly strategic behavior in tackling the CTF.

The fact that an AI agent could accomplish nearly half of the tasks without human intervention underscores how powerful well-orchestrated AI can be in a pentesting context. However, this feat also stayed within the simpler challenge range—a reminder that human expertise and reasoning is still critical for the tougher problems.

## The glue for your redefined cyber operations

Beyond the context of a single CTF, Attack of the Agents hints at profound implications for real-world cybersecurity workflows.

The event proved that AI assistants can dramatically speed up routine tasks (one newbie finished an entire CTF in under 40 minutes!), which suggests that in day-to-day security operations, AI could similarly automate the low-hanging fruit.

For example, participants had the AI generate detailed solution write-ups, which in a professional setting could translate to an AI drafting incident reports or documentation automatically, allowing analysts to focus on the actual investigation.

“The autonomous agent’s performance is a glimpse of how agent orchestration might work in a SOC: an AI agent could be tasked with enumerating a network, collecting logs, or performing initial triage on alerts, then handing off to humans for the complex analysis. MCP essentially provides the glue to make such orchestration possible, by allowing an AI to interact with many tools and systems in a governed way.”

– Pavlos Kolios, Product Manager @ Hack The Box

The broader cybersecurity industry is embracing AI and “agentic” automation in various forms.

-
Microsoft’s recently introduced Security Copilot <https://www.microsoft.com/en-us/security/business/ai-machine-learning/microsoft-security-copilot> is a generative AI-powered assistant for security teams, designed to help defenders work “at the speed and scale of AI” by leveraging global threat intelligence and internal data. Early versions of Security Copilot can summarize incidents, recommend remediation steps, and even integrate with tools like Sentinel to respond to threats.

-
Google has announced Sec-PaLM <https://blog.google/technology/ai/google-palm-2-ai-large-language-model/>, a specialized large language model tuned for cybersecurity applications. Sec-PaLM is used to analyze and explain malicious scripts and help detect threats faster than a human analyst might.

These examples from tech giants underline a common theme: AI in cybersecurity is all about augmenting human teams with intelligent automation.

What we saw in Attack of the Agents is a glimpse of this AI-assisted future. By integrating an open protocol like MCP, Hack The Box enabled a level of human–AI teaming and automation that we usually only talk about in theory.

The event showed that even relatively inexperienced users, empowered by AI copilots, can achieve results on par with seasoned experts—a powerful demonstration of team augmentation in action.

It also highlighted that humans and AI agents each have complementary strengths: AI is tireless, fast, and great at parsing data or code, while humans provide intuition, context, and ethical judgment. The optimal workflow is one that leverages both, which is exactly what an MCP server should be built to facilitate.

Going forward, we can expect CTFs (and cyber defense exercises in general) to evolve – easy tasks might be handled by AI by default, pushing humans to develop even more advanced skills.

Attack of the Agents provided an initial blueprint for integrating AI into cyber workflows: use AI agents to augment and accelerate and build systems that let human experts and AI coordinate seamlessly as a team.

## Capture the next flag with your AI agent at your fingertips

AI can accelerate skill development, lower entry barriers, and even handle autonomous tasks under the right conditions. But it also taught us about balancing speed with understanding, and the importance of guiding AI and humans to work hand-in-hand.

Ready to see this in action? If you’re intrigued by the MCP integration and how it transforms cyber education, check out Hack The Box Model Context Protocol (MCP) and join the waitlist <https://www.hackthebox.ai/>.

By getting involved early, you’ll be at the forefront of the AI revolution.

And why not take inspiration from this event to level up your own team?

Consider setting up a CTF <https://ctf.hackthebox.com/marketplace> focusing on AI security challenges or plug your own with AI agents in the mix. In the age of agentic AI, we are providing the best platform to benchmark capabilities of both humans and AI teammates! Now is the perfect time to start that journey.

JOIN THE MCP WAITLIST <https://www.hackthebox.ai/>

BUILD YOUR CTF <https://ctf.hackthebox.com/pack/ai-prompt-injection-essentials>

##  Latest articles

 The latest news and updates, direct from Hack The Box

  View all

###  The AI silent killers your dashboard will never show you

 Artificial Intelligence

 6 min read

  <https://www.hackthebox.com/blog/the-ai-silent-killer>

    <https://www.hackthebox.com/blog/author/dimimele>   dimimele  <https://www.hackthebox.com/blog/author/dimimele>
  October 12, 2026

###  The Unappraised Half of the Cyber Workforce: Building Readiness for Human and Agentic Teams

 Artificial Intelligence

 7 min read

  <https://www.hackthebox.com/blog/human-ai-cyber-workforce-readiness>

    <https://www.hackthebox.com/blog/author/sportybartlett>   SportyBartlett  <https://www.hackthebox.com/blog/author/sportybartlett>
  October 6, 2026

###  We Stress-Tested Five Cybersecurity Leaders. Here’s What They Taught Us About Humans and AI.

 Artificial Intelligence

 5 min read

  <https://www.hackthebox.com/blog/humans-ai-cybersecurity-leadership-lessons>

    <https://www.hackthebox.com/blog/author/sportybartlett>   SportyBartlett  <https://www.hackthebox.com/blog/author/sportybartlett>
  August 18, 2026

  View all

### Receive our weekly blog digest

###