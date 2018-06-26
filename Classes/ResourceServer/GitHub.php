<?php
declare(strict_types=1);

namespace Mfc\OAuth2\ResourceServer;

use Github\Client;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Github as GitHubOAuthProvider;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Saltedpasswords\Salt\SaltFactory;

/**
 * Class GitHub
 * @package Mfc\OAuth2\ResourceServer
 * @author Christian Spoo <cs@marketing-factory.de>
 */
class GitHub extends AbstractResourceServer
{
    /**
     * @var string
     */
    private $providerName;
    /**
     * @var string
     */
    private $projectName;
    /**
     * @var int
     */
    private $adminUserLevel;
    /**
     * @var array
     */
    private $githubDefaultGroups;
    /**
     * @var int
     */
    private $userOption;
    /**
     * @var AbstractProvider
     */
    private $oauthProvider;
    /**
     * @var bool
     */
    private $repositoryDetailsLoaded = false;
    /**
     * @var Client
     */
    private $githubApiClient;
    /**
     * @var array
     */
    private $githubRepositoryDetails;

    /**
     * GitHub constructor.
     * @param string $clientId
     * @param string $clientSecret
     * @param string $providerName
     * @param string $githubAdminUserLevel
     * @param string $githubDefaultGroups
     * @param string $githubUserOption
     * @param null|string $projectName
     */
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $providerName,
        string $githubAdminUserLevel,
        string $githubDefaultGroups,
        string $githubUserOption,
        ?string $projectName
    ) {
        $this->providerName = $providerName;
        $this->projectName = $projectName;
        $this->adminUserLevel = (int) $githubAdminUserLevel;
        $this->githubDefaultGroups = GeneralUtility::trimExplode(',', $githubDefaultGroups, true);
        $this->userOption = (int) $githubUserOption;

        $this->oauthProvider = new GitHubOAuthProvider([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $this->getRedirectUri($providerName),
        ]);
        $this->githubApiClient = new Client();
        $this->githubApiClient->authenticate($clientId, $clientSecret, Client::AUTH_URL_CLIENT_ID);
    }

    /**
     * @return AbstractProvider
     */
    public function getOAuthProvider(): AbstractProvider
    {
        return $this->oauthProvider;
    }

    /**
     * @return string
     */
    public function getAuthorizationUrl(): string
    {
        return $this->oauthProvider->getAuthorizationUrl([
            'scope' => ['user']
        ]);
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return bool
     */
    public function userShouldBeAdmin(ResourceOwnerInterface $user): bool
    {
        $this->loadUserDetails($user);
        if (!is_array($this->githubRepositoryDetails)) {
            return false;
        }

        $permissions = $this->githubRepositoryDetails['permissions'];

        // Grant admin access from Developer level onwards
        return in_array('write', $permissions);
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return \DateTime|null
     */
    public function userExpiresAt(ResourceOwnerInterface $user): ?\DateTime
    {
        return null;
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return bool
     */
    public function userIsActive(ResourceOwnerInterface $user): bool
    {
        $this->loadUserDetails($user);
        if (!is_array($this->githubRepositoryDetails)) {
            return false;
        }

        $permissions = $this->githubRepositoryDetails['permissions'];

        // Grant admin access from Developer level onwards
        return in_array('read', $permissions);
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return string
     */
    public function getOAuthIdentifier(ResourceOwnerInterface $user): string
    {
        $userData = $user->toArray();

        return $this->providerName . '|' . $userData['id'];
    }

    /**
     * @param ResourceOwnerInterface $user
     */
    public function loadUserDetails(ResourceOwnerInterface $user): void
    {
        if (!$user instanceof GithubResourceOwner) {
            throw new \InvalidArgumentException(
                'Resource owner "' . (string)$user . '" is no suitable GitHub resource owner'
            );
        }

        if ($this->repositoryDetailsLoaded) {
            return;
        }

        if (empty($this->projectName)) {
            return;
        }

        /** @var Client $gitlabClient */
        $repo = $this->githubApiClient->repos()->collaborators()->permission('marketing-factory', 'oauth2', $user->getNickname());
//        $repo = $this->githubApiClient->repo()->show($user->getNickname(), $this->projectName);

        try {
            $this->githubRepositoryDetails = $repo;
        } catch (\Exception $ex) {
            // User not authorized to access this project
        }

        $this->repositoryDetailsLoaded = true;
    }

    /**
     * @param ResourceOwnerInterface $user
     * @param array $currentRecord
     * @param array $authentificationInformation
     * @return array
     */
    public function updateUserRecord(
        ResourceOwnerInterface $user,
        array $currentRecord,
        array $authentificationInformation
    ): array {
        /** @var GithubResourceOwner $user */

        if (!is_array($currentRecord)) {
            $saltingInstance = SaltFactory::getSaltingInstance(null);

            $currentRecord = [
                'pid' => 0,
                'password' => $saltingInstance->getHashedPassword(md5(uniqid()))
            ];
        }

        $currentRecord = array_merge(
            $currentRecord,
            [
                'email' => $user->getEmail(),
                'realname' => $user->getName(),
                'username' => $this->getUsernameFromUser($user),
                /*'usergroup' => $this->getUserGroupsForUser(
                    $this->githubDefaultGroups,
                    $this->adminUserLevel,
                    $authentificationInformation['db_groups']['table']
                ),*/
                'options' => $this->userOption
            ]
        );

        return $currentRecord;
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return string
     */
    public function getUsernameFromUser(ResourceOwnerInterface $user): string
    {
        /** @var GithubResourceOwner $user */
        return substr($this->providerName . '_' . $user->getNickname(), 0, 50);
    }

    /**
     * @param ResourceOwnerInterface $user
     * @return string
     */
    public function getEmailFromUser(ResourceOwnerInterface $user): string
    {
        /** @var GithubResourceOwner $user */
        return $user->getEmail();
    }
}
