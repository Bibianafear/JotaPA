package com.example.demo.jotapa.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.jotapa.model.entity.CompanyEntity;
import com.example.demo.jotapa.service.CompanyService;

@RestController
public class CompanyController {

	@Autowired
	private CompanyService service;
	
	@PostMapping("/addCompany")
	public CompanyEntity addCompany(@RequestBody CompanyEntity company) {
		return service.saveCompany(company);
	}
	@PostMapping("addCompanies")
	public List< CompanyEntity> addCompanies(@RequestBody List<CompanyEntity> companies) {
		return service.saveCompanies(companies);
	}
	@GetMapping("companies")
	public List<CompanyEntity> findAllCompanies(){
		return service.getCompanies();
	}
	@GetMapping("company/{id}")
	public CompanyEntity getCompany(@PathVariable int id) {
		return service.getCompany(id);
	}
	
	//@GetMapping("company/{name}")
	//public CompanyEntity getByName(@PathVariable String name) {
	//	return service.getByName(name);
	//}
	@PutMapping("updateCompany")
	public CompanyEntity updateCompany (@RequestBody CompanyEntity company) {
		return service.updateCompany(company);
	}
	@DeleteMapping("deleteCompany/{id}")
	public String deleteCompany(@PathVariable int id ) {
		return service.deleteById(id);
	}
	
	@PatchMapping("/{id}")
	public CompanyEntity updatePartially (@PathVariable int id, @RequestBody Map<String,Object> fields) {
		return service.updateProductByFields(id, fields);
	}
}
