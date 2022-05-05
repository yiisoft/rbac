<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use DateTime;

/**
 * Items are RBAC hierarchy entities that could be assigned to the user.
 * Both roles and permissions are items.
 */
abstract class Item
{
    public const TYPE_ROLE = 'role';
    public const TYPE_PERMISSION = 'permission';

    /**
     * @var string The name of the item. This must be globally unique.
     */
    private string $name;

    /**
     * @var string The item description.
     */
    private string $description = '';

    /**
     * @var string|null Name of the rule associated with this item.
     */
    private ?string $ruleName = null;

    /**
     * @var DateTime|null UNIX timestamp representing the item creation time.
     */
    private ?DateTime $createdAt = null;

    /**
     * @var DateTime|null UNIX timestamp representing the item updating time.
     */
    private ?DateTime $updatedAt = null;

    /**
     * @param string $name The name of the item. This must be globally unique.
     */
    final public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @return string Type of the item.
     */
    abstract public function getType(): string;

    /**
     * @return string Authorization item name.
     */
    final public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return static
     */
    final public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    /**
     * @return static
     */
    final public function withDescription(string $description): self
    {
        $new = clone $this;
        $new->description = $description;
        return $new;
    }

    final public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * @return static
     */
    final public function withRuleName(?string $ruleName): self
    {
        $new = clone $this;
        $new->ruleName = $ruleName;
        return $new;
    }

    final public function getRuleName(): ?string
    {
        return $this->ruleName;
    }

    /**
     * @return static
     */
    final public function withCreatedAt(DateTime $createdAt): self
    {
        $new = clone $this;
        $new->createdAt = $createdAt;
        return $new;
    }

    final public function getCreatedAt(): ?DateTime
    {
        return $this->createdAt;
    }

    /**
     * @return static
     */
    final public function withUpdatedAt(DateTime $updatedAt): self
    {
        $new = clone $this;
        $new->updatedAt = $updatedAt;
        return $new;
    }

    final public function getUpdatedAt(): ?DateTime
    {
        return $this->updatedAt;
    }

    final public function hasCreatedAt(): bool
    {
        return $this->createdAt !== null;
    }

    final public function hasUpdatedAt(): bool
    {
        return $this->updatedAt !== null;
    }

    /**
     * @return array Authorization item attribute values indexed by attribute names.
     *
     * @psalm-return array{
     *     name:string,
     *     description:string,
     *     ruleName:string|null,
     *     type:string,
     *     updatedAt:DateTime|null,
     *     createdAt:DateTime|null,
     * }
     */
    final public function getAttributes(): array
    {
        $createdAt = $this->getUpdatedAt();
        if ($createdAt instanceof DateTime) {
            $createdAt = $createdAt->format("Y-m-d H:i:s");
        }
        $updatedAt = $this->getCreatedAt();
        if ($updatedAt instanceof DateTime) {
            $updatedAt = $updatedAt->format("Y-m-d H:i:s");
        }
        return [
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'ruleName' => $this->getRuleName(),
            'type' => $this->getType(),
            'updatedAt' => $createdAt,
            'createdAt' => $updatedAt,
        ];
    }
}
