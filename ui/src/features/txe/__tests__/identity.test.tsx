// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { UserPreferencesProvider } from '@/contexts/UserPreference';
import { I18nProvider } from '@/i18n/I18nProvider';

import { AccessRequestPending } from '../components/identity/AccessRequestPending';
import { EmptyPrivateInbox } from '../components/identity/EmptyPrivateInbox';
import { NoAccessYet } from '../components/identity/NoAccessYet';
import { NotFoundOrNotShared } from '../components/identity/NotFoundOrNotShared';
import { SharedWithYou } from '../components/identity/SharedWithYou';

function inLocale(locale: 'en' | 'zh-CN' | 'ja', ui: React.ReactElement) {
  localStorage.setItem('user_preferences', JSON.stringify({ locale }));
  return render(
    <UserPreferencesProvider>
      <I18nProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </I18nProvider>
    </UserPreferencesProvider>
  );
}

afterEach(() => {
  localStorage.clear();
});

describe('NoAccessYet', () => {
  it('asks for access only when the person presses the button', () => {
    const onRequestAccess = vi.fn();
    const onSignOut = vi.fn();
    inLocale(
      'en',
      <NoAccessYet
        username="ada"
        onRequestAccess={onRequestAccess}
        onSignOut={onSignOut}
      />
    );
    expect(screen.getByTestId('txe-no-access')).toHaveTextContent(
      'You are signed in as ada, but this server has not given your account access to any jobs.'
    );
    expect(onRequestAccess).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Request access' }));
    expect(onRequestAccess).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });

  it('says only that the account is signed in when it has no username', () => {
    inLocale(
      'en',
      <NoAccessYet onRequestAccess={vi.fn()} onSignOut={vi.fn()} />
    );
    expect(screen.getByTestId('txe-no-access')).toHaveTextContent(
      'You are signed in, but this server has not given your account access to any jobs.'
    );
  });

  it('disables the button while a request is being sent and shows why one failed', () => {
    inLocale(
      'en',
      <NoAccessYet
        requesting
        requestError="the hub did not answer"
        onRequestAccess={vi.fn()}
        onSignOut={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: 'Requesting…' })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(
      'The request was not recorded: the hub did not answer'
    );
  });

  it('shows a username as text, not markup', () => {
    const { container } = inLocale(
      'en',
      <NoAccessYet
        username="<img src=x onerror=alert(1)>"
        onRequestAccess={vi.fn()}
        onSignOut={vi.fn()}
      />
    );
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByTestId('txe-no-access')).toHaveTextContent(
      '<img src=x onerror=alert(1)>'
    );
  });

  it('is translated', () => {
    inLocale(
      'zh-CN',
      <NoAccessYet
        username="ada"
        onRequestAccess={vi.fn()}
        onSignOut={vi.fn()}
      />
    );
    expect(screen.getByRole('heading')).toHaveTextContent('你还没有访问权限');
    expect(screen.getByTestId('txe-no-access')).toHaveTextContent(
      '你已以 ada 的身份登录'
    );
    expect(
      screen.getByRole('button', { name: '申请访问' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '退出登录' })
    ).toBeInTheDocument();
  });
});

describe('AccessRequestPending', () => {
  it('says when the request was recorded and offers only Sign Out', () => {
    const onSignOut = vi.fn();
    inLocale(
      'en',
      <AccessRequestPending
        requestedAt={new Date(Date.now() - 5 * 60 * 1000).toISOString()}
        onSignOut={onSignOut}
      />
    );
    const panel = screen.getByTestId('txe-access-pending');
    expect(panel).toHaveTextContent('Access requested');
    expect(panel).toHaveTextContent(/Your request was recorded .*ago\./);
    expect(panel).toHaveTextContent(
      'The platform administrator has to approve it before this server shows you any jobs.'
    );
    expect(screen.getAllByRole('button')).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });

  it('is translated', () => {
    inLocale(
      'ja',
      <AccessRequestPending
        requestedAt={new Date().toISOString()}
        onSignOut={vi.fn()}
      />
    );
    expect(screen.getByRole('heading')).toHaveTextContent(
      'アクセスをリクエストしました'
    );
    expect(
      screen.getByRole('button', { name: 'ログアウト' })
    ).toBeInTheDocument();
  });
});

describe('EmptyPrivateInbox', () => {
  it('explains what will appear', () => {
    inLocale('en', <EmptyPrivateInbox />);
    expect(screen.getByTestId('txe-inbox-first')).toHaveTextContent(
      'You have no jobs yetJobs you register appear here, and so do jobs another engineer shares with you.'
    );
  });

  it('is translated', () => {
    inLocale('ja', <EmptyPrivateInbox />);
    expect(screen.getByTestId('txe-inbox-first')).toHaveTextContent(
      'まだジョブがありません'
    );
  });
});

describe('NotFoundOrNotShared', () => {
  it('gives one answer for a missing job and one not shared, with a way back', () => {
    inLocale('en', <NotFoundOrNotShared />);
    expect(screen.getByRole('heading')).toHaveTextContent('Job not found');
    expect(screen.getByTestId('txe-job-not-found')).toHaveTextContent(
      'This job does not exist, or it has not been shared with you.'
    );
    expect(screen.getByRole('link', { name: /Job inbox/ })).toHaveAttribute(
      'href',
      '/txe'
    );
  });

  it('is translated', () => {
    inLocale('zh-CN', <NotFoundOrNotShared />);
    expect(screen.getByRole('heading')).toHaveTextContent('未找到作业');
    expect(
      screen.getByRole('link', { name: /作业收件箱/ })
    ).toBeInTheDocument();
  });
});

describe('SharedWithYou', () => {
  it('names the owner who shared the job', () => {
    inLocale('en', <SharedWithYou ownerName="Grace" />);
    expect(screen.getByTestId('txe-shared-with-you')).toHaveTextContent(
      'Shared with you by Grace'
    );
  });

  it('is translated', () => {
    inLocale('ja', <SharedWithYou ownerName="Grace" />);
    expect(screen.getByTestId('txe-shared-with-you')).toHaveTextContent(
      'Grace から共有'
    );
  });
});
