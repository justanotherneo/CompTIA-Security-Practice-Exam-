import random as r
from data import question_data

class Question:
    def __init__(self, question, answer, correct, choices, user_answer):
        self.question = question
        self.answer = answer
        self.correct = correct
        self.choices = choices
        self.user_answer = user_answer
        self.asked = []
        self.user_answers = []
        self.correct_answers = []
        self.correct_choices = []
        self.incorrect_answers = []
        self.questions_asked = []  # Store each question text for review
        self.choices_asked = []    # Store the choices for each question asked

    # Get a question and present it to the user
    def ask_question(self):

        choice = r.choice(range(len(question_data)))

        while choice in self.asked:
            choice = r.choice(range(len(question_data)))

        # Get question data and store it in Question attribute lists
        self.question = question_data[choice]['question']
        self.answer = question_data[choice]['answer']
        self.correct = question_data[choice]['correct']
        self.choices = question_data[choice]['options']

        # Ask the user the question
        self.user_answer = input(f'{self.question}\n{self.choices}\n').lower()

        # Quit immediately if the user enters 'q'
        if self.user_answer in ['q', 'quit']:
            return True

        # Handle bad input
        if self.user_answer not in ['a', 'b', 'c', 'd']:
            print('Invalid input. Please try again. Enter only the letter of the answer you wish to select. '
                  'If you wish to quit, enter \'q\' or \'quit\'.')
            self.user_answer = input(f'{self.question}\n{self.choices}\n').lower()

            if self.user_answer in ['q', 'quit']:
                return True

            if self.user_answer not in ['a', 'b', 'c', 'd']:
                print('Invalid selection. Moving to the next question.')
                return False

        # Add the user's choice to tracking lists
        self.asked.append(choice)
        self.questions_asked.append(self.question)
        self.user_answers.append(self.user_answer)
        self.correct_answers.append(self.answer)
        self.correct_choices.append(self.correct)
        self.choices_asked.append(self.choices)

        # If the user gets the question wrong, add it to the 'incorrect_answers' list
        if self.user_answer != self.correct:
            self.incorrect_answers.append(self.question)

        return False

    # Check the user's score once the test is completed
    def score_test(self):
        # Calculate the total score (4 points per question)
        total = len(self.asked)
        correct_count = sum(
            1 for i in range(total) if self.user_answers[i] == self.correct_choices[i]
        )
        score = correct_count * 4
        max_score = total * 4

        print(f'\nYou scored a {score} / {max_score}\n')

        # Display incorrect answers
        if correct_count < total:
            print("Review of Incorrect Answers:")
            letter_index = {'a': 0, 'b': 1, 'c': 2, 'd': 3}
            for i in range(total):
                if self.user_answers[i] != self.correct_choices[i]:
                    print(f'Question: {self.questions_asked[i]}')
                    print(f'Correct Answer: {self.correct_answers[i]}')
                    user_letter = self.user_answers[i]
                    choice_text = self.choices_asked[i][letter_index[user_letter]]
                    print(f'You Chose: {choice_text}\n')
