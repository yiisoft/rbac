<?php

namespace Yiisoft\Rbac;

/**
 * For more details and usage information on Item, see the [guide article on security authorization](guide:security-authorization).
 */
abstract class Item implements ItemInterface
{
    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';

    /**
     * @var string the name of the item. This must be globally unique.
     */
    private $name;

    /**
     * @var string the item description
     */
    private $description = '';

    /**
     * @var string name of the rule associated with this item
     */
    private $ruleName;

    /**
     * @var int UNIX timestamp representing the item creation time
     */
    private $createdAt;

    /**
     * @var int UNIX timestamp representing the item updating time
     */
    private $updatedAt;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    abstract public function getType(): string;

    public function getName(): string
    {
        return $this->name;
    }

    public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    public function withDescription(string $description): self
    {
        $new = clone $this;
        $new->description = $description;
        return $new;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function withRuleName(?string $ruleName): self
    {
        $new = clone $this;
        $new->ruleName = $ruleName;
        return $new;
    }

    public function getRuleName(): ?string
    {
        return $this->ruleName;
    }

    public function withCreatedAt(int $createdAt): self
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }

    public function withUpdatedAt(int $updatedAt): self
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    public function getUpdatedAt(): ?int
    {
        return $this->updatedAt;
    }
}
