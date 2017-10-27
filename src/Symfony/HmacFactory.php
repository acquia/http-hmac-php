<?php

namespace Acquia\Hmac\Symfony;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;

class HmacFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.hmac.' . $id;
        $container->setDefinition($providerId, new ChildDefinition('hmac.security.authentication.provider'));

        $listenerId = 'security.authentication.listener.hmac.' . $id;
        $container->setDefinition($listenerId, new ChildDefinition('hmac.security.authentication.listener'));

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'hmac_auth';
    }

    public function addConfiguration(NodeDefinition $node)
    {
    }
}
