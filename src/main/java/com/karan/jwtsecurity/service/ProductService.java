package com.karan.jwtsecurity.service;

import com.karan.jwtsecurity.entity.Product;
import com.karan.jwtsecurity.repository.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    private final ProductRepository productRepository;
    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }
    // create
    public Product save(Product product) {
        return productRepository.save(product);
    }
    // get all
    public List<Product> findAll() {
        return productRepository.findAll();
    }
    // get by id
    public Product findById(Long id) {
        return productRepository.findById(id).get();
    }
    // update
    public Product updateProduct(Long id,Product product) {
        Product existingProduct = productRepository.findById(id).orElseThrow(null);
        existingProduct.setName(product.getName());
        existingProduct.setDescription(product.getDescription());
        existingProduct.setPrice(product.getPrice());
        return productRepository.save(existingProduct);
    }
    //delete by id
    public void deleteProduct(Long id) throws Exception {
        if(!productRepository.existsById(id)) {
            throw  new Exception("product not found");
        }
        productRepository.deleteById(id);
    }
}
