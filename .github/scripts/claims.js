// Issue claims: /assign, /unassign and /extend comments, and a daily job that
// reminds and then releases claims with no activity.
//
// Runs from .github/workflows/claims.yml through actions/github-script, always
// from the default branch, never from a pull request's code.

const REMIND_AFTER_DAYS = 10;
const RELEASE_AFTER_DAYS = 14;
const MAX_OPEN_CLAIMS = 3;
const FIRST_TIMER_LABEL = "good first issue";
const NOT_CLAIMABLE_LABELS = ["roadmap"];
const REMINDER_MARKER = "<!-- skillshield-claim-reminder -->";
const DAY_MS = 24 * 60 * 60 * 1000;

const HOW_IT_WORKS =
  `If there is no activity from you for ${REMIND_AFTER_DAYS} days you'll get a reminder, ` +
  `and after ${RELEASE_AFTER_DAYS} days the issue is released for someone else. ` +
  "Any comment from you counts as activity, and an open pull request that mentions this issue " +
  "pauses the clock. Comment `/extend` if you need more time, or `/unassign` to let it go.";

function parseCommand(body) {
  const first = (body || "").trim().split(/\r?\n/)[0].trim().toLowerCase();
  const match = first.match(/^\/(assign|unassign|extend)(?:\s|$)/);
  return match ? match[1] : null;
}

function isBot(user) {
  return !user || user.type === "Bot" || user.login.endsWith("[bot]");
}

function labelNames(issue) {
  return (issue.labels || []).map((l) => (typeof l === "string" ? l : l.name).toLowerCase());
}

async function searchCount(github, q) {
  const { data } = await github.rest.search.issuesAndPullRequests({ q, per_page: 1 });
  return data.total_count;
}

async function reply(github, owner, repo, number, body) {
  await github.rest.issues.createComment({ owner, repo, issue_number: number, body });
}

async function handleComment({ github, context }) {
  const { owner, repo } = context.repo;
  const { issue, comment } = context.payload;
  if (!issue || !comment || issue.pull_request || isBot(comment.user)) return "ignored";

  const command = parseCommand(comment.body);
  if (!command) return "ignored";

  const user = comment.user.login;
  const number = issue.number;
  const assignees = (issue.assignees || []).map((a) => a.login);
  const labels = labelNames(issue);
  const contributeUrl = `https://github.com/${owner}/${repo}/contribute`;

  if (issue.state !== "open") {
    await reply(github, owner, repo, number, `@${user} this issue is closed, so it can't be claimed. Have a look at the [open issues](${contributeUrl}).`);
    return "closed";
  }

  if (command === "unassign") {
    if (!assignees.includes(user)) {
      await reply(github, owner, repo, number, `@${user} this issue isn't assigned to you, so there's nothing to release.`);
      return "not-assignee";
    }
    await github.rest.issues.removeAssignees({ owner, repo, issue_number: number, assignees: [user] });
    await reply(github, owner, repo, number, `@${user} released, thanks for letting us know. The issue is open for someone else.`);
    return "unassigned";
  }

  if (command === "extend") {
    if (!assignees.includes(user)) {
      await reply(github, owner, repo, number, `@${user} this issue isn't assigned to you. Comment \`/assign\` to claim it.`);
      return "not-assignee";
    }
    await reply(github, owner, repo, number, `@${user} no problem, the clock is reset. It stays yours.`);
    return "extended";
  }

  // command === "assign"
  if (NOT_CLAIMABLE_LABELS.some((l) => labels.includes(l))) {
    await reply(github, owner, repo, number, `@${user} this is a tracking issue, so it isn't claimed itself. Pick one of the issues it lists and comment \`/assign\` there.`);
    return "not-claimable";
  }
  if (assignees.includes(user)) {
    await reply(github, owner, repo, number, `@${user} this issue is already assigned to you.`);
    return "already-yours";
  }
  if (assignees.length > 0) {
    const who = assignees.map((a) => `@${a}`).join(", ");
    await reply(github, owner, repo, number, `@${user} this issue is already assigned to ${who}. Have a look at the [other open issues](${contributeUrl}). If this one is released, you can claim it then.`);
    return "taken";
  }

  if (labels.includes(FIRST_TIMER_LABEL)) {
    const merged = await searchCount(github, `repo:${owner}/${repo} is:pr is:merged author:${user}`);
    if (merged > 0) {
      await reply(github, owner, repo, number, `@${user} thanks for offering! \`good first issue\` is kept for people who haven't had a pull request merged here yet, so newcomers always have a way in. Since you have, the [\`help wanted\`](https://github.com/${owner}/${repo}/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) issues are yours to pick from.`);
      return "not-first-timer";
    }
    const firstTimerClaims = await searchCount(github, `repo:${owner}/${repo} is:issue is:open label:"${FIRST_TIMER_LABEL}" assignee:${user}`);
    if (firstTimerClaims > 0) {
      await reply(github, owner, repo, number, `@${user} you already have a \`good first issue\` assigned. Please finish or \`/unassign\` that one first, so other newcomers get a turn.`);
      return "one-first-timer-issue";
    }
  }

  const openClaims = await searchCount(github, `repo:${owner}/${repo} is:issue is:open assignee:${user}`);
  if (openClaims >= MAX_OPEN_CLAIMS) {
    await reply(github, owner, repo, number, `@${user} you already have ${openClaims} open issues assigned. Please finish or \`/unassign\` one of them before claiming another.`);
    return "too-many";
  }

  const { data } = await github.rest.issues.addAssignees({ owner, repo, issue_number: number, assignees: [user] });
  if (!(data.assignees || []).some((a) => a.login === user)) {
    await reply(github, owner, repo, number, `@${user} GitHub didn't accept the assignment. A maintainer will assign it to you by hand.`);
    return "assign-failed";
  }
  await reply(github, owner, repo, number, `@${user} it's yours, thanks for picking this up! Please read [CONTRIBUTING.md](https://github.com/${owner}/${repo}/blob/main/CONTRIBUTING.md) before you start.\n\n${HOW_IT_WORKS}`);
  return "assigned";
}

// Last time `user` showed activity on the issue: being assigned, or commenting.
function lastActivity(timeline, user) {
  let last = 0;
  for (const e of timeline) {
    const actor = (e.actor || e.user || {}).login;
    if (e.event === "assigned" && e.assignee && e.assignee.login === user) {
      last = Math.max(last, Date.parse(e.created_at));
    } else if (e.event === "commented" && actor === user) {
      last = Math.max(last, Date.parse(e.created_at));
    }
  }
  return last;
}

function hasOpenLinkedPr(timeline) {
  return timeline.some(
    (e) =>
      e.event === "cross-referenced" &&
      e.source &&
      e.source.issue &&
      e.source.issue.pull_request &&
      e.source.issue.state === "open",
  );
}

function remindedSince(timeline, since) {
  return timeline.some(
    (e) => e.event === "commented" && Date.parse(e.created_at) > since && (e.body || "").includes(REMINDER_MARKER),
  );
}

async function releaseStale({ github, context, now = Date.now() }) {
  const { owner, repo } = context.repo;
  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner, repo, state: "open", assignee: "*", per_page: 100,
  });
  const actions = [];
  for (const issue of issues) {
    if (issue.pull_request) continue;
    if (NOT_CLAIMABLE_LABELS.some((l) => labelNames(issue).includes(l))) continue;
    const timeline = await github.paginate(github.rest.issues.listEventsForTimeline, {
      owner, repo, issue_number: issue.number, per_page: 100,
    });
    if (hasOpenLinkedPr(timeline)) continue;
    for (const { login } of issue.assignees || []) {
      if (login === owner) continue; // maintainer's own work is never released
      const last = lastActivity(timeline, login);
      if (!last) continue;
      const idleDays = (now - last) / DAY_MS;
      if (idleDays >= RELEASE_AFTER_DAYS) {
        await github.rest.issues.removeAssignees({ owner, repo, issue_number: issue.number, assignees: [login] });
        await reply(github, owner, repo, issue.number, `@${login} there's been no activity here for ${RELEASE_AFTER_DAYS} days, so this issue is released for someone else. Thank you for your interest: if you'd like to pick it back up, comment \`/assign\` while it's still free.`);
        actions.push({ issue: issue.number, user: login, action: "released" });
      } else if (idleDays >= REMIND_AFTER_DAYS && !remindedSince(timeline, last)) {
        await reply(github, owner, repo, issue.number, `${REMINDER_MARKER}\n@${login} just checking in: are you still working on this? It will be released in ${RELEASE_AFTER_DAYS - Math.floor(idleDays)} days if there's no activity. Comment \`/extend\` to keep it, or \`/unassign\` to let it go. No pressure either way.`);
        actions.push({ issue: issue.number, user: login, action: "reminded" });
      }
    }
  }
  return actions;
}

module.exports = { handleComment, releaseStale, parseCommand, lastActivity, hasOpenLinkedPr, REMINDER_MARKER };
