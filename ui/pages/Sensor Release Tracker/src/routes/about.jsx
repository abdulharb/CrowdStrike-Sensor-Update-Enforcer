import React from "react";
import { SlDetails } from "@shoelace-style/shoelace/dist/react";

function About() {
  return (
    <div className="p-6 max-w-2xl space-y-6 text-text-and-icons">
      <div>
        <h2 className="type-xl text-text-and-icons mb-1">About Sensor Release Tracker</h2>
        <p className="type-sm text-body-and-labels">
          Tracks CrowdStrike Falcon sensor versions and their release standings across your environment.
        </p>
      </div>

      <SlDetails summary="Release Standings">
        <div className="space-y-3 type-sm text-body-and-labels">
          <p><strong className="text-titles-and-attributes">N</strong> — The latest generally available sensor release. Most current version; recommended for new deployments.</p>
          <p><strong className="text-titles-and-attributes">N-1</strong> — One version behind current. Still supported and commonly deployed across production environments.</p>
          <p><strong className="text-titles-and-attributes">N-2</strong> — Two versions behind current. Approaching end-of-support; plan an upgrade soon.</p>
          <p><strong className="text-titles-and-attributes">Untagged</strong> — Older versions no longer actively tagged. Prioritize upgrading hosts on these builds.</p>
        </div>
      </SlDetails>

      <SlDetails summary="Stages">
        <div className="space-y-3 type-sm text-body-and-labels">
          <p><strong className="text-titles-and-attributes">Prod</strong> — Generally available release on production channels.</p>
          <p><strong className="text-titles-and-attributes">Early Adopter (EA)</strong> — Pre-release version available to early adopter channels for validation before broad rollout. Shown as a secondary line under N in the platform cards when it differs from the prod N version.</p>
        </div>
      </SlDetails>

      <SlDetails summary="How to Use">
        <div className="space-y-3 type-sm text-body-and-labels">
          <p>The <strong className="text-titles-and-attributes">platform cards</strong> at the top show the current N, N-1, and N-2 versions per OS. Click a card to filter the table to that platform; click again to clear.</p>
          <p>Use the <strong className="text-titles-and-attributes">filter pills</strong> to narrow by platform, standing, or stage. The <strong className="text-titles-and-attributes">search box</strong> matches against version strings and build numbers.</p>
          <p>Click the <strong className="text-titles-and-attributes">chevron</strong> on a table row to expand the standing history timeline for that build.</p>
          <p>Click any <strong className="text-titles-and-attributes">column header</strong> to sort; click again to reverse direction.</p>
          <p>Use the <strong className="text-titles-and-attributes">Refresh</strong> button in the top-right to sync the latest data from the collection.</p>
        </div>
      </SlDetails>
    </div>
  );
}

export { About };
