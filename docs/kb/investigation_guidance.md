## Things to know

- **A risk score is a reason to look.** Never a verdict.
- **Half the cases are legitimate.** Many look suspicious. An agent that blocks everything scores badly.
- **The known patterns are not the only ones.** Some activity in this data fits none of the five. Noticing it and describing it in your own words is scored.
- **Devices and regions connect people.** A device profile or a billing region shared across many cards in a short window is worth a look. Some cases can only be solved by asking what happened on *other* cards.
- **The V, C, D, M and numeric id columns are real model features with no names.** You may use them as signals. Say so in your evidence rather than pretending to know what V127 means.
- **Customer and analyst replies are not provided.** If your agent asks the customer or requests step-up authentication, simulate the response in your own system and record what you assumed in `evidence_requests`.

