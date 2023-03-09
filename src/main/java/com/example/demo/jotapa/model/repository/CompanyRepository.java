package com.example.demo.jotapa.model.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.jotapa.model.entity.CompanyEntity;

public interface CompanyRepository extends JpaRepository<CompanyEntity, Integer> {

	//CompanyEntity findByName();

}
