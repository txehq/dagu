import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { useConfig } from '@/contexts/ConfigContext';
import { UserAuthProvider } from '@/api/v1/schema';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { User, LogOut, Key, Users } from 'lucide-react';
import { ChangePasswordModal } from './ChangePasswordModal';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';
import { oidcLoginURL } from '@/lib/oidcLogin';

type UserMenuProps = {
  isCollapsed?: boolean;
  // side is where the menu opens: above the trigger at the foot of the
  // sidebar, below it in a top bar.
  side?: 'top' | 'bottom';
  // actingFor is the display name of the owner a person signed in through
  // the identity provider acts for. A person's hub role decides nothing, so
  // it is shown instead of the role.
  actingFor?: string;
};

/**
 * Renders a user dropdown menu with profile info, a change-password action, and sign-out.
 *
 * The menu is rendered only when built-in authentication is enabled and a user is authenticated.
 *
 * @returns The user menu JSX element when shown, or `null` when authentication is not available.
 */
export function UserMenu({
  isCollapsed = false,
  side = 'top',
  actingFor,
}: UserMenuProps) {
  const { t } = useI18n();
  const { user, logout, isAuthenticated } = useAuth();
  const config = useConfig();
  const navigate = useNavigate();
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  // Don't show if auth is not builtin or user is not authenticated
  if (config.authMode !== 'builtin' || !isAuthenticated || !user) {
    return null;
  }

  const handleLogout = async () => {
    if (signingOut) {
      return;
    }
    setSigningOut(true);
    const result = await logout();
    // This browser is signed out in every case; the login page says so when
    // the hub did not confirm that the session ended.
    navigate(result === 'unconfirmed' ? '/login?signout=unconfirmed' : '/login');
  };

  // Switching account ends this hub session like Sign Out, then asks the
  // provider for a fresh sign-in instead of reusing its session. When the
  // hub could not confirm the sign-out, the login page says so and nothing
  // more happens.
  const handleSwitchAccount = async () => {
    if (signingOut) {
      return;
    }
    setSigningOut(true);
    const result = await logout();
    if (result === 'unconfirmed') {
      navigate('/login?signout=unconfirmed');
      return;
    }
    window.location.assign(oidcLoginURL(config.basePath, 'login'));
  };
  const canSwitchAccount =
    config.oidcEnabled && user.authProvider === UserAuthProvider.oidc;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            className="flex items-center gap-2 h-7 px-2 rounded hover:bg-sidebar-foreground/5 text-sidebar-foreground cursor-pointer w-full"
            style={{ transition: 'background-color 150ms ease' }}
            title={isCollapsed ? user.username : undefined}
          >
            <User className="h-4 w-4 shrink-0" />
            <span
              className="text-xs font-medium overflow-hidden whitespace-nowrap"
              style={{
                transition:
                  'opacity 200ms cubic-bezier(0.4, 0, 0.2, 1), transform 200ms cubic-bezier(0.4, 0, 0.2, 1), max-width 280ms cubic-bezier(0.4, 0, 0.2, 1)',
                opacity: isCollapsed ? 0 : 1,
                maxWidth: isCollapsed ? '0px' : '120px',
                transform: isCollapsed ? 'translateX(-8px)' : 'translateX(0)',
              }}
            >
              {user.username}
            </span>
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align={isCollapsed ? 'center' : 'end'}
          side={side}
          className="w-56"
        >
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium">{user.username}</p>
              {actingFor !== undefined ? (
                <p
                  className="text-xs text-muted-foreground"
                  data-testid="user-menu-owner"
                >
                  <I18nText
                    text="Acting for {owner}"
                    values={{ owner: actingFor }}
                  />
                </p>
              ) : (
                <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground capitalize w-fit">
                  {user.role}
                </span>
              )}
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {(!user.authProvider ||
            user.authProvider === UserAuthProvider.builtin) && (
            <>
              <DropdownMenuItem onClick={() => setShowChangePassword(true)}>
                <Key className="h-4 w-4 mr-2" />
                {t('auth.changePassword')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
            </>
          )}
          {canSwitchAccount && (
            <DropdownMenuItem
              onClick={() => void handleSwitchAccount()}
              disabled={signingOut}
            >
              <Users className="h-4 w-4 mr-2" />
              <I18nText text="Switch account" />
            </DropdownMenuItem>
          )}
          <DropdownMenuItem
            onClick={() => void handleLogout()}
            disabled={signingOut}
            className="text-error focus:text-error"
          >
            <LogOut className="h-4 w-4 mr-2" />
            {t('auth.signOut')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ChangePasswordModal
        open={showChangePassword}
        onClose={() => setShowChangePassword(false)}
      />
    </>
  );
}
