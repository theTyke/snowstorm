package org.ihtsdo.elasticsnomed.core.data.services;

import io.kaicode.elasticvc.api.BranchService;
import org.ihtsdo.elasticsnomed.AbstractTest;
import org.ihtsdo.elasticsnomed.TestConfig;
import org.ihtsdo.elasticsnomed.core.data.domain.*;
import org.ihtsdo.elasticsnomed.core.data.domain.expression.Expression;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


import static org.ihtsdo.elasticsnomed.core.data.domain.Concepts.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = TestConfig.class)
public class ExpressionServiceTest extends AbstractTest {

	@Autowired
	private BranchService branchService;

	@Autowired
	private ConceptService conceptService;
	
	@Autowired
	private ExpressionService expressionService;
	
	private static final String EXPRESSION_TEST_BRANCH = "EXPRESSION-TEST";
	int relId = 1;
	
	Concept root;
	Concept isa;
	Concept attribute;
	Concept target1;
	Concept target2;
	List<Concept> allKnownConcepts = new ArrayList<>();
	
	boolean setupComplete = false;
	
	@Before
	public void setup() throws ServiceException {
		if (!setupComplete) {
			branchService.create(EXPRESSION_TEST_BRANCH);
			root = createConcept(SNOMEDCT_ROOT, null, PRIMITIVE);
			//ISA needs to exist to use in it's own definition!
			isa = new Concept(ISA);
			isa = createConcept(ISA, root, PRIMITIVE);
			attribute = createConcept ("91", root, PRIMITIVE);
			target1 = createConcept ("92", root, PRIMITIVE);
			target2 = createConcept ("93", root, PRIMITIVE);
		}
		setupComplete = true;
	}

	@Test
	public void testConceptAuthoringFormSimple() throws ServiceException {

		Concept concept1 = createConcept ("1", root, PRIMITIVE);
		Concept concept2 = createConcept ("2", concept1, PRIMITIVE);
		Concept concept3 = createConcept ("3", concept2, FULLY_DEFINED);
		Concept concept4 = createConcept ("4", concept3, FULLY_DEFINED);
		concept4.addRelationship(createRelationship(attribute, target1));
		concept4.addRelationship(createRelationship(attribute, target2));
		
		conceptService.createUpdate(allKnownConcepts, EXPRESSION_TEST_BRANCH);
		
		/*Expression exp = expressionService.getConceptAuthoringForm(concept4.getConceptId(), EXPRESSION_TEST_BRANCH);
		//Expecting two attributes, and a single focus concept of concept 2
		assertEquals(2, exp.getAttributes().size());
		assertEquals(1, exp.getConcepts());
		assertEquals(concept2, exp.getConcepts().get(0));*/
	}
	
	private Relationship createRelationship(Concept type, Concept target) {
		Relationship r = new Relationship(nextRel(), type.getConceptId(),target.getConceptId());
		r.setCharacteristicType(Concepts.INFERRED_RELATIONSHIP);
		return r;
	}

	@Test
	public void testConceptAuthoringFormComplex() throws ServiceException {
		
	}
	
	@Test
	public void testConceptAuthoringFormAttributeGroups() throws ServiceException {
		
	}

	private String nextRel() {
		Integer nextRel = relId++;
		return nextRel.toString();
	}

	private Concept createConcept(String sctId, Concept parent, String definitionStatusSctId) throws ServiceException {
		Concept concept = conceptService.create(new Concept(sctId), EXPRESSION_TEST_BRANCH)
				.setDefinitionStatusId(definitionStatusSctId)
				.addDescription(fsn("concept" + sctId));
		if (parent != null) {
			concept.addRelationship(createRelationship(isa, parent));
		}
		allKnownConcepts.add(concept);
		return concept;
	}

	private Description fsn(String term) {
		Description description = new Description(term);
		description.setTypeId(FSN);
		return description;
	}

}
