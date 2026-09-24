## Glossary

| Term | Meaning here |
|---|---|
| **Risk score** | A number from 0 to 1 the bank's model attached to every transaction. High means "look at this." It is often wrong in both directions. Never treat it as the answer |
| **Closed case** | An investigation the bank already finished, July to October. Either confirmed fraud or cleared as a false alarm. The only place the truth is written down |
| **Case pack** | The 20 alerts you investigate, all from November and December. Your exam |
| **Trigger** | Why an alert exists: the model scored it high, a customer complained, or an analyst asked |
| **Pattern** | The kind of fraud. Five are documented below. Some in the data are not |
| **Channel** | `in_person` (product code W, no device record) or `online` (all other product codes, device record present) |
| **Identity record** | The device and connection details Vesta captured for online transactions: device type and model, OS, browser, screen, proxy flag, and encoded ratings |
| **Billing region** | `addr1`: an anonymized code for where the card is billed. `addr2` is the country code; 87 is the home country |
| **Exposure** | Total dollars in the fraud episode you identified |
| **Case** (as a deliverable) | The bank's internal record of your investigation. Part 1 of your answer |
| **SAR** | Suspicious Activity Report. The regulatory filing a bank must make for confirmed or strongly suspected fraud above certain thresholds. Part 2 of your answer, only when the policy calls for it |
| **Next best action** | What the bank should do now, and who has to approve it. Part 3 of your answer |
| **Approval route** | `auto` the agent may act alone; `L1` a team lead must approve; `L2` a fraud manager must approve |
| **MCP** | Model Context Protocol. How your agent calls TigerGraph as a set of tools |
| **GraphRAG** | Retrieving evidence from the graph and text from documents, and giving both to the LLM to reason over, instead of raw data |

