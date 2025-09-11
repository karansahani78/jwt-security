package com.karan.jwtsecurity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;

@Entity
@Table(name = "product_info")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(name = "product_info", nullable = false)
    @NotEmpty(message = "name must required for the product")
    private String name;
    @Column(name = "product_price", nullable = false)
    @NotEmpty(message = "price is  required")
    private BigDecimal price;
    @Column(name = "product_description", nullable = false)
    @NotEmpty(message = "description is required")
    private String description;
}
