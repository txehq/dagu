// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { Check, Copy } from 'lucide-react';
import React from 'react';
import { Link } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useConfig } from '@/contexts/ConfigContext';
import { actsForOwner, useTxeIdentity } from '@/features/txe/identity';
import { useI18n } from '@/i18n/I18nProvider';
import { copyText } from '@/lib/clipboard';

import {
  MIN_TAG,
  hubAddress,
  hubAddressRefused,
  isBeforeMinTag,
  isTag,
  setupCommands,
  smokeCommands,
  tagVersion,
} from './setupCommands';

// CommandBlock shows a command to copy. Copying is the only thing it does:
// nothing on this page runs a command or asks the machine anything.
function CommandBlock({
  command,
  label,
}: {
  command: string;
  label: string;
}): React.ReactElement {
  const { t } = useI18n();
  const [state, setState] = React.useState<'idle' | 'copied' | 'failed'>(
    'idle'
  );
  const reset = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  React.useEffect(
    () => () => {
      if (reset.current) clearTimeout(reset.current);
    },
    []
  );
  const copy = async () => {
    const ok = await copyText(command);
    setState(ok ? 'copied' : 'failed');
    if (reset.current) clearTimeout(reset.current);
    reset.current = setTimeout(() => setState('idle'), 2000);
  };
  return (
    <div className="relative mt-1.5 rounded-md border border-border bg-muted">
      <pre className="max-h-72 overflow-auto px-3 py-2 pr-10 font-mono text-xs leading-5 text-foreground">
        <code>{command}</code>
      </pre>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="absolute right-1 top-1"
        aria-label={t('integrations.devSetup.copy', { label })}
        onClick={() => void copy()}
      >
        {state === 'copied' ? <Check /> : <Copy />}
      </Button>
      <span className="sr-only" aria-live="polite">
        {state === 'copied'
          ? t('integrations.devSetup.copied')
          : state === 'failed'
            ? t('integrations.devSetup.copyFailed')
            : ''}
      </span>
      {state === 'failed' && (
        <p className="px-3 pb-2 text-xs text-destructive">
          {t('integrations.devSetup.copyFailed')}
        </p>
      )}
    </div>
  );
}

function Expected({ children }: { children: React.ReactNode }) {
  const { t } = useI18n();
  return (
    <p className="mt-1 text-xs text-muted-foreground">
      <span className="font-medium text-foreground">
        {t('integrations.devSetup.expected')}
      </span>{' '}
      {children}
    </p>
  );
}

function Step({
  n,
  title,
  children,
}: {
  n: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <li className="rounded-md border border-border bg-card px-3 py-2.5">
      <h4 className="text-sm font-medium text-foreground">
        <span className="mr-1.5 text-muted-foreground">{n}.</span>
        {title}
      </h4>
      <div className="mt-1 space-y-1 text-xs text-muted-foreground">
        {children}
      </div>
    </li>
  );
}

// DeveloperSetup is the guide to setting up the TXE developer CLI and the
// txe-dagu-jobs skill on a person's own machine, and checking that it works.
// A browser cannot see that machine, so it never reports the machine's
// state: every check is a command whose output is the answer. The one thing
// it reads is who the hub takes this browser's account to be, and it says so.
export function DeveloperSetup(): React.ReactElement {
  const { t } = useI18n();
  const config = useConfig();
  const { identity } = useTxeIdentity();
  const [tag, setTag] = React.useState(MIN_TAG);

  const hub = hubAddress(window.location.origin, config.apiURL);
  const cmd = setupCommands(tag, hub);
  const smoke = smokeCommands();
  const version = tagVersion(tag);
  const owner = actsForOwner(identity) ? identity?.owners[0] : undefined;

  return (
    <section aria-labelledby="dev-setup-title" className="flex flex-col gap-3">
      <div>
        <h3 id="dev-setup-title" className="text-base font-semibold">
          {t('integrations.devSetup.title')}
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('integrations.devSetup.intro')}
        </p>
        <ul className="mt-1.5 list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
          <li>{t('integrations.devSetup.factNoWorker')}</li>
          <li>{t('integrations.devSetup.factNoKeys')}</li>
          <li>{t('integrations.devSetup.factSeparate')}</li>
        </ul>
        {owner && (
          <p
            className="mt-1.5 text-xs text-muted-foreground"
            data-testid="dev-setup-browser-identity"
          >
            {t('integrations.devSetup.browserIdentity', {
              owner: owner.display_name
                ? `${owner.display_name} (${owner.owner_id})`
                : owner.owner_id,
            })}
          </p>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="dev-setup-tag" className="text-xs font-medium">
          {t('integrations.devSetup.tagLabel')}
        </label>
        <Input
          id="dev-setup-tag"
          className="h-7 max-w-xs font-mono text-xs"
          value={tag}
          spellCheck={false}
          aria-describedby="dev-setup-tag-help"
          aria-invalid={!isTag(tag)}
          onChange={(e) => setTag(e.target.value.trim())}
        />
        <p id="dev-setup-tag-help" className="text-xs text-muted-foreground">
          {t('integrations.devSetup.tagHelp', { min: MIN_TAG })}
        </p>
        {!isTag(tag) && (
          <p role="alert" className="text-xs text-destructive">
            {t('integrations.devSetup.tagInvalid', { min: MIN_TAG })}
          </p>
        )}
        {isBeforeMinTag(tag) && (
          <p role="alert" className="text-xs text-warning">
            {t('integrations.devSetup.tagTooOld', { tag, min: MIN_TAG })}
          </p>
        )}
      </div>

      <ol className="flex flex-col gap-2">
        <Step n={1} title={t('integrations.devSetup.prereqTitle')}>
          <p>{t('integrations.devSetup.prereqBody')}</p>
          <CommandBlock
            command={cmd.prerequisites}
            label={t('integrations.devSetup.prereqTitle')}
          />
          <Expected>{t('integrations.devSetup.prereqExpected')}</Expected>
        </Step>
        <Step n={2} title={t('integrations.devSetup.installTitle')}>
          <p>{t('integrations.devSetup.installBody')}</p>
          <CommandBlock
            command={cmd.install}
            label={t('integrations.devSetup.installTitle')}
          />
          <Expected>{t('integrations.devSetup.installExpected')}</Expected>
        </Step>
        <Step n={3} title={t('integrations.devSetup.checkTitle')}>
          <p>{t('integrations.devSetup.checkBody')}</p>
          <CommandBlock
            command={cmd.check}
            label={t('integrations.devSetup.checkTitle')}
          />
          <Expected>
            {t('integrations.devSetup.checkExpected', {
              version: version ?? '<version>',
            })}
          </Expected>
        </Step>
        <Step n={4} title={t('integrations.devSetup.loginTitle')}>
          <p>{t('integrations.devSetup.loginBody')}</p>
          {hubAddressRefused(hub) && (
            <p role="alert" className="text-warning">
              {t('integrations.devSetup.loginHttp')}
            </p>
          )}
          <CommandBlock
            command={cmd.login}
            label={t('integrations.devSetup.loginTitle')}
          />
          <CommandBlock
            command={cmd.loginNoBrowser}
            label={t('integrations.devSetup.loginNoBrowser')}
          />
          <p>{t('integrations.devSetup.loginSshBody')}</p>
          <CommandBlock
            command={cmd.sshForward}
            label={t('integrations.devSetup.loginSsh')}
          />
          <Expected>{t('integrations.devSetup.loginExpected')}</Expected>
        </Step>
        <Step n={5} title={t('integrations.devSetup.whoamiTitle')}>
          <CommandBlock
            command={cmd.whoami}
            label={t('integrations.devSetup.whoamiTitle')}
          />
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            <li>{t('integrations.devSetup.whoamiBound')}</li>
            <li>{t('integrations.devSetup.whoamiUnbound')}</li>
            <li>{t('integrations.devSetup.whoamiPending')}</li>
          </ul>
        </Step>
        <Step n={6} title={t('integrations.devSetup.machineTitle')}>
          <p>{t('integrations.devSetup.machineBody')}</p>
          <CommandBlock
            command={cmd.machineCreate}
            label={t('integrations.devSetup.machineTitle')}
          />
          <Expected>
            {t('integrations.devSetup.machineExpected')}{' '}
            <Link to="/txe/machines" className="text-primary hover:underline">
              {t('integrations.devSetup.machinesLink')}
            </Link>
          </Expected>
        </Step>
        <Step n={7} title={t('integrations.devSetup.workerTitle')}>
          <p>{t('integrations.devSetup.workerBody')}</p>
          <CommandBlock
            command={cmd.enrol}
            label={t('integrations.devSetup.workerTitle')}
          />
          <Expected>{t('integrations.devSetup.workerExpected')}</Expected>
        </Step>
        <Step n={8} title={t('integrations.devSetup.skillTitle')}>
          <p>{t('integrations.devSetup.skillBody')}</p>
          <CommandBlock
            command="dagu txe skill status"
            label={t('integrations.devSetup.skillTitle')}
          />
          <Expected>{t('integrations.devSetup.skillExpected')}</Expected>
        </Step>
      </ol>

      <div>
        <h3 className="text-base font-semibold">
          {t('integrations.devSetup.verifyTitle')}
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('integrations.devSetup.verifyIntro')}
        </p>
      </div>
      <ol
        className="flex flex-col gap-2"
        aria-label={t('integrations.devSetup.verifyTitle')}
      >
        <Step n={1} title={t('integrations.devSetup.stageCliTitle')}>
          <p>{t('integrations.devSetup.stageCliProof')}</p>
        </Step>
        <Step n={2} title={t('integrations.devSetup.stageIdentityTitle')}>
          <p>{t('integrations.devSetup.stageIdentityProof')}</p>
        </Step>
        <Step n={3} title={t('integrations.devSetup.stageMachineTitle')}>
          <CommandBlock
            command={cmd.doctor}
            label={t('integrations.devSetup.stageMachineTitle')}
          />
          <p>{t('integrations.devSetup.stageMachineProof')}</p>
        </Step>
        <Step n={4} title={t('integrations.devSetup.stageJobTitle')}>
          <p>{t('integrations.devSetup.smokeIntro')}</p>
          <h5 className="pt-1 text-xs font-medium text-foreground">
            {t('integrations.devSetup.smokeCreate')}
          </h5>
          <CommandBlock
            command={smoke.create}
            label={t('integrations.devSetup.smokeCreate')}
          />
          <Expected>{t('integrations.devSetup.smokeCreateExpected')}</Expected>
          <h5 className="pt-1 text-xs font-medium text-foreground">
            {t('integrations.devSetup.smokeDryRun')}
          </h5>
          <CommandBlock
            command={smoke.dryRun}
            label={t('integrations.devSetup.smokeDryRun')}
          />
          <Expected>{t('integrations.devSetup.smokeDryRunExpected')}</Expected>
          <h5 className="pt-1 text-xs font-medium text-foreground">
            {t('integrations.devSetup.smokeRegister')}
          </h5>
          <p className="text-warning">
            {t('integrations.devSetup.smokeRegisterNote')}
          </p>
          <CommandBlock
            command={smoke.register}
            label={t('integrations.devSetup.smokeRegister')}
          />
          <Expected>
            {t('integrations.devSetup.smokeRegisterExpected')}
          </Expected>
          <h5 className="pt-1 text-xs font-medium text-foreground">
            {t('integrations.devSetup.smokeVerify')}
          </h5>
          <CommandBlock
            command={smoke.verify}
            label={t('integrations.devSetup.smokeVerify')}
          />
          <Expected>{t('integrations.devSetup.smokeVerifyExpected')}</Expected>
          <h5 className="pt-1 text-xs font-medium text-foreground">
            {t('integrations.devSetup.smokeInspect')}
          </h5>
          <CommandBlock
            command={smoke.inspect}
            label={t('integrations.devSetup.smokeInspect')}
          />
          <Expected>
            {t('integrations.devSetup.smokeInspectExpected')}{' '}
            <Link to="/txe" className="text-primary hover:underline">
              {t('integrations.devSetup.inboxLink')}
            </Link>
          </Expected>
          <p>{t('integrations.devSetup.smokeExpiry')}</p>
        </Step>
      </ol>
    </section>
  );
}
