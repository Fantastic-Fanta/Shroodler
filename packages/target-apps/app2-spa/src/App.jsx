import React, { useEffect, useState } from "react";

export function App() {
  const [session, setSession] = useState(null);
  const [route, setRoute] = useState(window.location.pathname);

  useEffect(() => {
    fetch("/api/session")
      .then((r) => r.json())
      .then(setSession);
    const onPop = () => setRoute(window.location.pathname);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  function go(path) {
    window.history.pushState({}, "", path);
    setRoute(path);
  }

  if (!session) {
    return <p>Loading…</p>;
  }

  if (route === "/account") {
    return (
      <section>
        <h1>Account</h1>
        <form action="/api/save" method="POST">
          <input type="email" name="email" />
          <input type="hidden" name="csrf" value="spa-csrf" />
          <button type="submit">Save</button>
        </form>
        <button type="button" onClick={() => go("/")}>
          Home
        </button>
      </section>
    );
  }

  if (route === "/billing") {
    return (
      <section>
        <h1>Billing</h1>
        <form action="/api/plan" method="POST">
          <input type="text" name="plan" />
          <button type="submit">Choose</button>
        </form>
        <button type="button" onClick={() => go("/")}>
          Home
        </button>
      </section>
    );
  }

  return (
    <section>
      <h1>SPA portal</h1>
      <p>Signed in as {session.user}.</p>
      <nav>
        <a href="/account" onClick={(e) => { e.preventDefault(); go("/account"); }}>
          Account
        </a>
      </nav>
      <button type="button" onClick={() => go("/billing")}>
        Billing
      </button>
      <form action="/api/invite" method="POST" id="invite-form">
        <input type="text" name="invitee" />
        <button type="submit">Invite</button>
      </form>
    </section>
  );
}
