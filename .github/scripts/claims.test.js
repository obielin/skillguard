// Tests for claims.js. Run with: node --test .github/scripts/claims.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const claims = require("./claims.js");

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-11-20T12:00:00Z");
const ago = (days) => new Date(NOW - days * DAY).toISOString();

// A fake GitHub client that records calls and answers search counts from a table.
function fakeGithub({ counts = {}, assignAccepted = true, issues = [], timelines = {} } = {}) {
  const calls = { comments: [], added: [], removed: [] };
  const github = {
    rest: {
      search: {
        issuesAndPullRequests: async ({ q }) => {
          const key = Object.keys(counts).find((k) => q.includes(k));
          return { data: { total_count: key ? counts[key] : 0 } };
        },
      },
      issues: {
        createComment: async ({ issue_number, body }) => calls.comments.push({ issue_number, body }),
        addAssignees: async ({ assignees }) => {
          calls.added.push(...assignees);
          return { data: { assignees: assignAccepted ? assignees.map((login) => ({ login })) : [] } };
        },
        removeAssignees: async ({ issue_number, assignees }) => calls.removed.push({ issue_number, assignees }),
        listForRepo: "listForRepo",
        listEventsForTimeline: "listEventsForTimeline",
      },
    },
    paginate: async (fn, args) => (fn === "listForRepo" ? issues : timelines[args.issue_number] || []),
  };
  return { github, calls };
}

function ctx({ body, user = "newbie", labels = [], assignees = [], state = "open", pr = false, bot = false }) {
  return {
    repo: { owner: "obielin", repo: "skillshield" },
    payload: {
      issue: {
        number: 30, state, labels: labels.map((name) => ({ name })),
        assignees: assignees.map((login) => ({ login })), ...(pr ? { pull_request: {} } : {}),
      },
      comment: { body, user: { login: bot ? "x[bot]" : user, type: bot ? "Bot" : "User" } },
    },
  };
}

test("parseCommand reads only a command at the start of the first line", () => {
  assert.equal(claims.parseCommand("/assign"), "assign");
  assert.equal(claims.parseCommand("  /ASSIGN please\nthanks"), "assign");
  assert.equal(claims.parseCommand("/unassign"), "unassign");
  assert.equal(claims.parseCommand("/extend"), "extend");
  assert.equal(claims.parseCommand("I'd like to /assign this"), null);
  assert.equal(claims.parseCommand("/assignment"), null);
  assert.equal(claims.parseCommand(""), null);
});

test("a newcomer can claim a good first issue", async () => {
  const { github, calls } = fakeGithub();
  const r = await claims.handleComment({ github, context: ctx({ body: "/assign", labels: ["good first issue"] }) });
  assert.equal(r, "assigned");
  assert.deepEqual(calls.added, ["newbie"]);
  assert.match(calls.comments[0].body, /it's yours/);
});

test("someone with a merged PR cannot take a good first issue", async () => {
  const { github, calls } = fakeGithub({ counts: { "is:merged author:newbie": 1 } });
  const r = await claims.handleComment({ github, context: ctx({ body: "/assign", labels: ["good first issue"] }) });
  assert.equal(r, "not-first-timer");
  assert.deepEqual(calls.added, []);
  assert.match(calls.comments[0].body, /help wanted/);
});

test("a newcomer holds one good first issue at a time", async () => {
  const { github, calls } = fakeGithub({ counts: { 'label:"good first issue" assignee:newbie': 1 } });
  const r = await claims.handleComment({ github, context: ctx({ body: "/assign", labels: ["good first issue"] }) });
  assert.equal(r, "one-first-timer-issue");
  assert.deepEqual(calls.added, []);
});

test("anyone can claim a help wanted issue, up to three open claims", async () => {
  const ok = fakeGithub({ counts: { "is:merged author:newbie": 5, "is:open assignee:newbie": 2 } });
  assert.equal(await claims.handleComment({ github: ok.github, context: ctx({ body: "/assign", labels: ["help wanted"] }) }), "assigned");
  const full = fakeGithub({ counts: { "is:open assignee:newbie": 3 } });
  assert.equal(await claims.handleComment({ github: full.github, context: ctx({ body: "/assign", labels: ["help wanted"] }) }), "too-many");
  assert.deepEqual(full.calls.added, []);
});

test("an issue that is already assigned cannot be taken", async () => {
  const { github, calls } = fakeGithub();
  const r = await claims.handleComment({ github, context: ctx({ body: "/assign", assignees: ["someone"] }) });
  assert.equal(r, "taken");
  assert.deepEqual(calls.added, []);
  assert.match(calls.comments[0].body, /@someone/);
});

test("roadmap tracking issues and closed issues cannot be claimed", async () => {
  const a = fakeGithub();
  assert.equal(await claims.handleComment({ github: a.github, context: ctx({ body: "/assign", labels: ["roadmap"] }) }), "not-claimable");
  const b = fakeGithub();
  assert.equal(await claims.handleComment({ github: b.github, context: ctx({ body: "/assign", state: "closed" }) }), "closed");
  assert.deepEqual([...a.calls.added, ...b.calls.added], []);
});

test("pull requests, bots and ordinary comments are ignored", async () => {
  const { github, calls } = fakeGithub();
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign", pr: true }) }), "ignored");
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign", bot: true }) }), "ignored");
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "Looks good to me" }) }), "ignored");
  assert.deepEqual(calls.comments, []);
});

test("/unassign releases only your own claim", async () => {
  const mine = fakeGithub();
  assert.equal(await claims.handleComment({ github: mine.github, context: ctx({ body: "/unassign", assignees: ["newbie"] }) }), "unassigned");
  assert.deepEqual(mine.calls.removed, [{ issue_number: 30, assignees: ["newbie"] }]);
  const theirs = fakeGithub();
  assert.equal(await claims.handleComment({ github: theirs.github, context: ctx({ body: "/unassign", assignees: ["someone"] }) }), "not-assignee");
  assert.deepEqual(theirs.calls.removed, []);
});

test("a failed assignment is reported instead of claimed", async () => {
  const { github, calls } = fakeGithub({ assignAccepted: false });
  assert.equal(await claims.handleComment({ github, context: ctx({ body: "/assign" }) }), "assign-failed");
  assert.match(calls.comments[0].body, /maintainer will assign/);
});

const staleIssue = (number, login, labels = []) => ({ number, assignees: [{ login }], labels: labels.map((name) => ({ name })) });
const assigned = (login, days) => ({ event: "assigned", assignee: { login }, actor: { login: "github-actions[bot]" }, created_at: ago(days) });
const commented = (login, days, body = "working on it") => ({ event: "commented", actor: { login }, created_at: ago(days), body });

test("a claim idle for 14 days is released", async () => {
  const { github, calls } = fakeGithub({ issues: [staleIssue(1, "newbie")], timelines: { 1: [assigned("newbie", 15)] } });
  const actions = await claims.releaseStale({ github, context: ctx({}), now: NOW });
  assert.deepEqual(actions, [{ issue: 1, user: "newbie", action: "released" }]);
  assert.deepEqual(calls.removed, [{ issue_number: 1, assignees: ["newbie"] }]);
});

test("a claim idle for 10 days gets one reminder, not two", async () => {
  const first = fakeGithub({ issues: [staleIssue(1, "newbie")], timelines: { 1: [assigned("newbie", 11)] } });
  assert.deepEqual(await claims.releaseStale({ github: first.github, context: ctx({}), now: NOW }), [{ issue: 1, user: "newbie", action: "reminded" }]);
  assert.match(first.calls.comments[0].body, /still working on this/);
  const again = fakeGithub({
    issues: [staleIssue(1, "newbie")],
    timelines: { 1: [assigned("newbie", 12), commented("github-actions[bot]", 1, claims.REMINDER_MARKER)] },
  });
  assert.deepEqual(await claims.releaseStale({ github: again.github, context: ctx({}), now: NOW }), []);
});

test("a recent comment, an open PR, the maintainer or a roadmap issue keeps the claim", async () => {
  const openPr = { event: "cross-referenced", created_at: ago(20), source: { issue: { pull_request: {}, state: "open" } } };
  const { github, calls } = fakeGithub({
    issues: [staleIssue(1, "newbie"), staleIssue(2, "newbie"), staleIssue(3, "obielin"), staleIssue(4, "newbie", ["roadmap"])],
    timelines: {
      1: [assigned("newbie", 30), commented("newbie", 2)],
      2: [assigned("newbie", 30), openPr],
      3: [assigned("obielin", 60)],
      4: [assigned("newbie", 60)],
    },
  });
  assert.deepEqual(await claims.releaseStale({ github, context: ctx({}), now: NOW }), []);
  assert.deepEqual(calls.removed, []);
});
