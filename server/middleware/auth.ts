import { MediaServerType } from '@server/constants/server';
import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import logger from '@server/logger';
import type {
  Permission,
  PermissionCheckOptions,
} from '@server/lib/permissions';
import { getSettings } from '@server/lib/settings';
import * as net from 'net';

export const checkUser: Middleware = async (req, _res, next) => {
  const settings = getSettings();
  let user: User | undefined | null;

  const userRepository = getRepository(User);
  let trustedProxy = false;

  // Check if the remoteSocketAddress we received the request
  // from is trusted!
  const socketAddress = req.socket.remoteAddress || '';

  if (net.isIPv4(socketAddress)) {
    trustedProxy =
      socketAddress === '127.0.0.1' ||
      settings.network.trustedProxies.v4.includes(socketAddress);
  } else if (net.isIPv6(socketAddress)) {
    trustedProxy =
      socketAddress === '::1' ||
      settings.network.trustedProxies.v6.includes(socketAddress);
  }

  if (req.header('X-API-Key') === settings.main.apiKey) {
    let userId = 1; // Work on original administrator account

    // If a User ID is provided, we will act on that user's behalf
    if (req.header('X-API-User')) {
      userId = Number(req.header('X-API-User'));
    }

    user = await userRepository.findOne({ where: { id: userId } });
  } else if (req.session?.userId) {
    user = await userRepository.findOne({
      where: { id: req.session.userId },
    });
  } else if (
    settings.network.trustProxy &&
    settings.network.forwardAuth.enabled &&
    trustedProxy
  ) {
    let { userHeader, emailHeader } = settings.network.forwardAuth;
    userHeader = userHeader.toLowerCase();
    emailHeader = emailHeader.toLowerCase();

    const hasUserHeader = userHeader !== '';
    const hasEmailHeader = emailHeader !== '';
    const userValue = (hasUserHeader && req.header(userHeader)) ?? '';
    const emailValue = (hasEmailHeader && req.header(emailHeader)) ?? '';

    // Match case-insensitively. Jellyfin's AuthenticateByName lowercases the
    // username before storing (so `jellyfinUsername` is `tina`), while most
    // IDPs preserve the original case in property mappings (`Tina`). Without
    // this, every fresh deploy needs either per-user DB fix-ups or a manual
    // lowercasing expression in the IDP — surprising in both cases.
    const qb = userRepository.createQueryBuilder('user');

    if (
      hasUserHeader &&
      hasEmailHeader &&
      userValue !== '' &&
      emailValue !== ''
    ) {
      // email & user header was specified so we must verify both
      qb.where(
        '(LOWER(user.jellyfinUsername) = LOWER(:user) OR LOWER(user.plexUsername) = LOWER(:user)) AND LOWER(user.email) = LOWER(:email)',
        { user: userValue, email: emailValue }
      );
      user = await qb.getOne();
    } else if (hasUserHeader && userValue !== '') {
      qb.where(
        'LOWER(user.jellyfinUsername) = LOWER(:user) OR LOWER(user.plexUsername) = LOWER(:user)',
        { user: userValue }
      );
      user = await qb.getOne();
    } else if (hasEmailHeader && emailValue !== '') {
      qb.where('LOWER(user.email) = LOWER(:email)', { email: emailValue });
      user = await qb.getOne();
    }

    // Auto-provision: if forward-auth identifies a new user that isn't in the
    // DB, create one on the fly with the default permission set. Opt-in so
    // existing deploys are unaffected. The userType matches whichever media
    // server is configured (Plex/Jellyfin/Emby) so existing per-userType
    // logic (avatars, server-specific UI) keeps working; falls back to
    // LOCAL when no media server is configured.
    if (
      !user &&
      settings.network.forwardAuth.autoProvision &&
      hasUserHeader &&
      userValue
    ) {
      const mediaServerType = settings.main.mediaServerType;
      const newUserType =
        mediaServerType === MediaServerType.PLEX
          ? UserType.PLEX
          : mediaServerType === MediaServerType.JELLYFIN
          ? UserType.JELLYFIN
          : mediaServerType === MediaServerType.EMBY
          ? UserType.EMBY
          : UserType.LOCAL;

      try {
        user = new User({
          // Email is required NOT NULL — synthesise a stable placeholder when
          // the IDP doesn't provide one. Admin can edit it afterwards.
          email: emailValue || `${userValue}@forward-auth.local`,
          plexUsername:
            newUserType === UserType.PLEX ? userValue : undefined,
          jellyfinUsername:
            newUserType === UserType.JELLYFIN ||
            newUserType === UserType.EMBY
              ? userValue
              : undefined,
          permissions: settings.main.defaultPermissions,
          userType: newUserType,
          // Required NOT NULL column; resolved client-side via Gravatar/avatarproxy.
          avatar: '',
        });
        await userRepository.save(user);
        logger.info(
          `Auto-provisioned user via forward-auth: ${userValue}`,
          { label: 'Auth', userId: user.id, userType: newUserType }
        );
      } catch (e) {
        logger.error(
          `Failed to auto-provision forward-auth user ${userValue}`,
          { label: 'Auth', errorMessage: (e as Error).message }
        );
        user = null;
      }
    }
  }
  if (user) {
    req.user = user;
  }

  req.locale = user?.settings?.locale
    ? user.settings.locale
    : settings.main.locale;

  next();
};

export const isAuthenticated = (
  permissions?: Permission | Permission[],
  options?: PermissionCheckOptions
): Middleware => {
  const authMiddleware: Middleware = (req, res, next) => {
    if (!req.user || !req.user.hasPermission(permissions ?? 0, options)) {
      res.status(403).json({
        status: 403,
        error: 'You do not have permission to access this endpoint',
      });
    } else {
      next();
    }
  };
  return authMiddleware;
};
