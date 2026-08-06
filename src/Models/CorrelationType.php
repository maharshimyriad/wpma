<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * CorrelationType — enum representing different types of threat correlations.
 */
enum CorrelationType: string
{
    case ATTACK_CHAIN    = 'attack_chain';
    case SHARED_IOC      = 'shared_ioc';
    case LOADER_CHAIN    = 'loader_chain';
    case FAMILY_CLUSTER  = 'family_cluster';
}
